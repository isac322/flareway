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

// Package gatewayapi translates Kubernetes Gateway API resources into Flareway's intermediate representation.
package gatewayapi

import (
	"fmt"
	"net/url"
	pathpkg "path"
	"slices"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/isac322/flareway/api/v1alpha1"
	"github.com/isac322/flareway/internal/authz"
	gatewaystatus "github.com/isac322/flareway/internal/gatewayapi/status"
	"github.com/isac322/flareway/internal/ir"
)

const allowOriginJWTDisableLabel = "flareway.bhyoo.com/allow-origin-jwt-disable"

// AUDSecret is the non-public handoff from the AccessApplication controller to
// the Gateway translator. Its values must never be copied to status or events.
type AUDSecret struct {
	AUD           string
	ApplicationID string
	Ready         bool
}

// AccessDestination is a Cloudflare Access destination compiled from a target.
type AccessDestination struct {
	Type        v1alpha1.AccessApplicationDestinationType
	URI         string
	Hostname    string
	CIDR        string
	PortRange   string
	L4Protocol  *v1alpha1.AccessL4Protocol
	VNetID      string
	MCPServerID string
	WorkerID    string
}

// AccessDataPlane identifies one isolated protection domain used by an app.
type AccessDataPlane struct {
	Tunnel           string
	Listener         string
	ProtectionDomain string
	EnvoyPort        int32
}

// AccessBypass describes an operator-owned child application for a public path
// nested beneath a protected destination.
type AccessBypass struct {
	Hostname string
	Path     string
}

// AccessAncestor identifies an object to which policy status is attached.
type AccessAncestor struct {
	Group     string
	Kind      string
	Namespace string
	Name      string
}

// AccessApplicationCompilation is the pure result consumed by both the
// AccessApplication and Gateway controllers.
type AccessApplicationCompilation struct {
	Accepted          bool
	Reason            string
	Message           string
	Destinations      []AccessDestination
	DataPlanes        []AccessDataPlane
	Bypass            []AccessBypass
	Ancestors         []AccessAncestor
	OriginJWTEnforced bool

	claims []accessClaim
}

type accessClaim struct {
	listener    string
	hostname    string
	routeName   string
	region      accessRegion
	wholeHost   bool
	shadow      bool
	specificity int
}

type accessRegion struct {
	kind string
	path string
}

const (
	accessRegionExact  = "Exact"
	accessRegionPrefix = "Prefix"
)

// CompileAccessApplication resolves one application against the same pure
// Gateway inputs used by Translate. It performs no Kubernetes or Cloudflare IO.
func CompileAccessApplication(in Inputs, application *v1alpha1.AccessApplication) AccessApplicationCompilation {
	if application == nil {
		return accessFailure("Invalid", "AccessApplication is nil")
	}
	base := in
	base.AccessApplications = nil
	base.AUDSecrets = nil
	gateway, _ := Translate(base)
	if gateway == nil {
		if len(application.Spec.TargetRefs) > 0 {
			return accessFailure("TargetNotFound", "Gateway target was not found")
		}
		return compileDeclaredAccessDestinations(in, application)
	}
	return compileAccessApplicationAgainstIR(in, gateway, application)
}

func compileAccessApplicationAgainstIR(in Inputs, gateway *ir.Gateway, application *v1alpha1.AccessApplication) AccessApplicationCompilation {
	result := AccessApplicationCompilation{
		Accepted: true,
		Reason:   "Accepted",
		Message:  "Access application targets are valid",
	}
	if application.Namespace != gateway.Key.Namespace {
		return accessFailure("RefNotPermitted", "AccessApplication targets must be in the Gateway namespace")
	}
	if in.CloudflareAccount != nil && application.Spec.AccountRef.Name != in.CloudflareAccount.Name {
		return accessFailure("RefNotPermitted", fmt.Sprintf("AccessApplication accountRef %q does not match Gateway account %q", application.Spec.AccountRef.Name, in.CloudflareAccount.Name))
	}
	if effectiveOriginJWTMode(application) == v1alpha1.AccessOriginJWTModeDisabled {
		namespace := namespaceByName(in.Namespaces, application.Namespace)
		if namespace == nil || namespace.Labels[allowOriginJWTDisableLabel] != "true" {
			return accessFailure("RefNotPermitted", "originJWT Disabled requires namespace label flareway.bhyoo.com/allow-origin-jwt-disable=true")
		}
	}

	pathScope, scoped, err := accessApplicationPathScope(application)
	if err != nil {
		return accessFailure("Invalid", err.Error())
	}
	seenDestination := make(map[string]struct{})
	seenAncestor := make(map[string]struct{})
	seenClaim := make(map[string]struct{})
	for _, target := range application.Spec.TargetRefs {
		group := string(target.Group)
		if group == "" {
			group = gatewayGroup
		}
		kind := string(target.Kind)
		if kind == "" {
			kind = "Gateway"
		}
		switch {
		case group == gatewayGroup && kind == "Gateway":
			if string(target.Name) != gateway.Key.Name {
				continue
			}
			matched := false
			specificity := 10
			if target.SectionName != nil {
				specificity = 15
			}
			region := accessRegion{kind: accessRegionPrefix, path: "/"}
			wholeHost := true
			if scoped {
				region = pathScope
				wholeHost = false
				specificity += 5
			}
			for _, domain := range gateway.Domains {
				if target.SectionName != nil && string(*target.SectionName) != domain.ListenerName {
					continue
				}
				for _, virtualHost := range domain.VirtualHosts {
					if virtualHost.Hostname == "" || virtualHost.Hostname == "*" {
						continue
					}
					matched = true
					if err := appendAccessDestination(&result, seenDestination, in, gateway, domain.ListenerName, virtualHost.Hostname, region); err != nil {
						return accessFailure("TargetNotFound", err.Error())
					}
					if len(virtualHost.Routes) == 0 {
						appendAccessClaim(&result, seenClaim, accessClaim{listener: domain.ListenerName, hostname: virtualHost.Hostname, region: region, wholeHost: wholeHost, shadow: scoped, specificity: specificity})
					}
					for _, route := range virtualHost.Routes {
						appendAccessClaim(&result, seenClaim, accessClaim{listener: domain.ListenerName, hostname: virtualHost.Hostname, routeName: route.Name, region: region, wholeHost: wholeHost, shadow: scoped, specificity: specificity})
					}
				}
			}
			if matched {
				appendAccessAncestor(&result, seenAncestor, AccessAncestor{Group: gatewayGroup, Kind: "Gateway", Namespace: gateway.Key.Namespace, Name: gateway.Key.Name})
			}
		case group == gatewayGroup && kind == "HTTPRoute":
			matched := false
			for _, domain := range gateway.Domains {
				for _, virtualHost := range domain.VirtualHosts {
					for _, route := range virtualHost.Routes {
						if route.Source.Namespace != application.Namespace || route.Source.Name != string(target.Name) {
							continue
						}
						if target.SectionName != nil && route.Source.RuleName != string(*target.SectionName) {
							continue
						}
						matched = true
						region, err := accessRegionForRoute(route)
						if err != nil {
							return accessFailure("Invalid", err.Error())
						}
						specificity := 20
						if target.SectionName != nil {
							specificity = 25
						}
						if scoped {
							region = pathScope
							specificity += 5
						}
						if err := appendAccessDestination(&result, seenDestination, in, gateway, domain.ListenerName, virtualHost.Hostname, region); err != nil {
							return accessFailure("TargetNotFound", err.Error())
						}
						appendAccessClaim(&result, seenClaim, accessClaim{listener: domain.ListenerName, hostname: virtualHost.Hostname, routeName: route.Name, region: region, shadow: scoped, specificity: specificity})
					}
				}
			}
			if matched {
				appendAccessAncestor(&result, seenAncestor, AccessAncestor{Group: gatewayGroup, Kind: "HTTPRoute", Namespace: application.Namespace, Name: string(target.Name)})
			}
		default:
			return accessFailure("Invalid", fmt.Sprintf("unsupported targetRef %s/%s", group, kind))
		}
	}

	declared := compileDeclaredAccessDestinations(in, application)
	if !declared.Accepted {
		return declared
	}
	for _, destination := range declared.Destinations {
		appendCompiledDestination(&result, seenDestination, destination)
	}
	result.Ancestors = append(result.Ancestors, declared.Ancestors...)
	if len(result.claims) == 0 && len(result.Destinations) == 0 {
		return accessFailure("TargetNotFound", "no targetRef or destination resolves to this Gateway")
	}
	result.OriginJWTEnforced = len(result.claims) > 0 && effectiveOriginJWTMode(application) == v1alpha1.AccessOriginJWTModeRequired
	sortAccessCompilation(&result)
	return result
}

func accessApplicationPathScope(application *v1alpha1.AccessApplication) (accessRegion, bool, error) {
	if application.Spec.PathScope == nil {
		return accessRegion{}, false, nil
	}
	path, err := normalizeAccessPath(application.Spec.PathScope.Value)
	if err != nil {
		return accessRegion{}, false, fmt.Errorf("normalize pathScope: %w", err)
	}
	matchType := application.Spec.PathScope.Type
	if matchType == "" {
		matchType = gatewayv1.PathMatchPathPrefix
	}
	switch matchType {
	case gatewayv1.PathMatchExact:
		return accessRegion{kind: accessRegionExact, path: path}, true, nil
	case gatewayv1.PathMatchPathPrefix:
		return accessRegion{kind: accessRegionPrefix, path: path}, true, nil
	default:
		return accessRegion{}, false, fmt.Errorf("pathScope uses unsupported match type %q", matchType)
	}
}

func compileDeclaredAccessDestinations(in Inputs, application *v1alpha1.AccessApplication) AccessApplicationCompilation {
	result := CompilePrivateDestinations(in, application)
	if !result.Accepted {
		return result
	}
	seen := make(map[string]struct{}, len(result.Destinations))
	for _, destination := range result.Destinations {
		seen[accessDestinationKey(destination)] = struct{}{}
	}
	for index, destination := range application.Spec.Destinations {
		switch destination.Type {
		case v1alpha1.AccessApplicationDestinationPrivate:
			continue
		case v1alpha1.AccessApplicationDestinationPublic:
			return accessFailure("Invalid", fmt.Sprintf("destinations[%d] cannot declare a public destination", index))
		case v1alpha1.AccessApplicationDestinationViaMCPServerPortal:
			if destination.ViaMCPServerPortal == nil {
				return accessFailure("Invalid", fmt.Sprintf("destinations[%d].viaMcpServerPortal is required", index))
			}
			appendCompiledDestination(&result, seen, AccessDestination{
				Type: v1alpha1.AccessApplicationDestinationViaMCPServerPortal, MCPServerID: destination.ViaMCPServerPortal.MCPServerID,
			})
		case v1alpha1.AccessApplicationDestinationWorker:
			if destination.Worker == nil {
				return accessFailure("Invalid", fmt.Sprintf("destinations[%d].worker is required", index))
			}
			appendCompiledDestination(&result, seen, AccessDestination{
				Type: v1alpha1.AccessApplicationDestinationWorker, WorkerID: destination.Worker.WorkerID,
			})
		case v1alpha1.AccessApplicationDestinationPreviewWorker:
			if destination.PreviewWorker == nil {
				return accessFailure("Invalid", fmt.Sprintf("destinations[%d].previewWorker is required", index))
			}
			appendCompiledDestination(&result, seen, AccessDestination{
				Type: v1alpha1.AccessApplicationDestinationPreviewWorker, WorkerID: destination.PreviewWorker.WorkerID,
			})
		case v1alpha1.AccessApplicationDestinationAllWorkers:
			appendCompiledDestination(&result, seen, AccessDestination{Type: v1alpha1.AccessApplicationDestinationAllWorkers})
		case v1alpha1.AccessApplicationDestinationAllPreviewWorkers:
			appendCompiledDestination(&result, seen, AccessDestination{Type: v1alpha1.AccessApplicationDestinationAllPreviewWorkers})
		default:
			return accessFailure("Invalid", fmt.Sprintf("destinations[%d] uses unsupported type %q", index, destination.Type))
		}
	}
	sortAccessCompilation(&result)
	return result
}

func applyAccessApplications(in Inputs, gateway *ir.Gateway, statuses *Statuses, now metav1.Time) {
	statuses.AccessApplications = make(map[types.NamespacedName]AccessApplicationCompilation)
	if gateway == nil || gateway.ConformanceMode || len(in.AccessApplications) == 0 {
		markPublicDomainsForHeaderStripping(gateway)
		return
	}

	applications := slices.Clone(in.AccessApplications)
	slices.SortFunc(applications, func(left, right v1alpha1.AccessApplication) int {
		if compared := left.CreationTimestamp.Compare(right.CreationTimestamp.Time); compared != 0 {
			return compared
		}
		return strings.Compare(left.Namespace+"/"+left.Name, right.Namespace+"/"+right.Name)
	})
	acceptedClaims := make(map[string][]accessClaim)
	for index := range applications {
		application := &applications[index]
		key := types.NamespacedName{Namespace: application.Namespace, Name: application.Name}
		compiled := compileAccessApplicationAgainstIR(in, gateway, application)
		if compiled.Accepted {
			for _, claim := range compiled.claims {
				for _, existing := range acceptedClaims[claim.hostname] {
					if existing.specificity == claim.specificity && accessRegionsOverlap(existing.region, claim.region) {
						compiled = rejectedAccessCompilation(compiled, "Conflicted", fmt.Sprintf("another equally specific AccessApplication already protects an overlapping path on %s", claim.hostname))
						break
					}
				}
				if !compiled.Accepted {
					break
				}
			}
		}
		if compiled.Accepted {
			for _, claim := range compiled.claims {
				acceptedClaims[claim.hostname] = append(acceptedClaims[claim.hostname], claim)
			}
		}
		statuses.AccessApplications[key] = compiled
	}

	original := slices.Clone(gateway.Domains)
	gateway.Domains = nil
	nextPublicPort := nextAccessEnvoyPort(original)
	dropped := make(map[types.NamespacedName][]string)
	remaining := make(map[types.NamespacedName]int)
	for _, domain := range original {
		for _, virtualHost := range domain.VirtualHosts {
			for _, route := range virtualHost.Routes {
				remaining[types.NamespacedName{Namespace: route.Source.Namespace, Name: route.Source.Name}]++
			}
		}
	}

	for _, domain := range original {
		for _, virtualHost := range domain.VirtualHosts {
			partitionAccessVirtualHost(in, gateway, statuses, domain, virtualHost, &nextPublicPort, dropped, remaining)
		}
	}
	applyAccessRouteDrops(statuses, in, dropped, remaining, now)
	for key, compiled := range statuses.AccessApplications {
		sortAccessCompilation(&compiled)
		statuses.AccessApplications[key] = compiled
	}
}

func partitionAccessVirtualHost(in Inputs, gateway *ir.Gateway, statuses *Statuses, base ir.ProtectionDomain, host ir.VirtualHost, nextPublicPort *int32, dropped map[types.NamespacedName][]string, remaining map[types.NamespacedName]int) {
	claimed := make(map[string][]ir.Route)
	public := make([]ir.Route, 0, len(host.Routes))
	wholeHost := make(map[string]bool)
	regions := make(map[string][]accessRegion)
	for _, route := range host.Routes {
		selectedByOwner := make(map[string]accessClaim)
		for key, compilation := range statuses.AccessApplications {
			if !compilation.Accepted {
				continue
			}
			owner := key.String()
			for _, claim := range compilation.claims {
				if claim.listener != base.ListenerName || claim.hostname != host.Hostname ||
					claim.routeName != route.Name && !claim.wholeHost {
					continue
				}
				selected, found := selectedByOwner[owner]
				if !found || claim.specificity > selected.specificity {
					selectedByOwner[owner] = claim
				}
			}
		}
		if len(selectedByOwner) == 0 {
			public = append(public, route)
			continue
		}
		consumingSpecificity := -1
		for _, selected := range selectedByOwner {
			if !selected.shadow && selected.specificity > consumingSpecificity {
				consumingSpecificity = selected.specificity
			}
		}
		for owner, selected := range selectedByOwner {
			if !selected.shadow && selected.specificity < consumingSpecificity {
				continue
			}
			wholeHost[owner] = wholeHost[owner] || selected.wholeHost
			regions[owner] = appendUniqueAccessRegion(regions[owner], selected.region)
			claimed[owner] = append(claimed[owner], route)
		}
	}
	if len(host.Routes) == 0 {
		for key, compilation := range statuses.AccessApplications {
			if !compilation.Accepted {
				continue
			}
			for _, claim := range compilation.claims {
				if claim.listener == base.ListenerName && claim.hostname == host.Hostname && claim.wholeHost {
					owner := key.String()
					wholeHost[owner] = true
					regions[owner] = appendUniqueAccessRegion(regions[owner], claim.region)
				}
			}
		}
	}

	if len(claimed) == 0 && len(wholeHost) == 0 {
		base.StripAccessHeaders = base.Guard == ir.GuardUnprotected
		base.VirtualHosts = []ir.VirtualHost{host}
		gateway.Domains = append(gateway.Domains, base)
		return
	}

	protectedRegions := make(map[string][]accessRegion)
	for owner, ownerRegions := range regions {
		for _, region := range ownerRegions {
			protectedRegions[owner] = appendUniqueAccessRegion(protectedRegions[owner], region)
		}
	}
	publicAllowed := authz.Evaluate(in.CloudflareAccount, namespaceByName(in.Namespaces, gateway.Key.Namespace), authz.Request{
		Hostname: host.Hostname, Exposure: v1alpha1.ExposurePublic, Unprotected: true,
	}).Allowed
	keptPublic := make([]ir.Route, 0, len(public))
	publicIngress := make([]ir.PathMatch, 0, len(public))
	for _, route := range public {
		q, err := accessRegionForRoute(route)
		message := ""
		switch {
		case route.Match.Type == ir.PathMatchRegularExpression || err != nil || q.kind != accessRegionExact && q.kind != accessRegionPrefix:
			message = "split hostname: public carve-outs must use Exact or PathPrefix matches"
		case !publicAllowed:
			message = "public carve-out requires unprotected grant for " + host.Hostname
		default:
			containers := make([]string, 0)
			overlaps := false
			bestSpecificity := -1
			for owner, ownerRegions := range protectedRegions {
				for _, p := range ownerRegions {
					if !accessRegionsOverlap(p, q) {
						continue
					}
					overlaps = true
					if !accessRegionContains(p, q) {
						continue
					}
					specificity := accessClaimSpecificity(statuses.AccessApplications[parseNamespacedName(owner)], base.ListenerName, host.Hostname, p)
					if specificity > bestSpecificity {
						bestSpecificity = specificity
						containers = []string{owner}
					} else if specificity == bestSpecificity {
						containers = append(containers, owner)
					}
				}
			}
			containers = uniqueStrings(containers)
			if overlaps && len(containers) != 1 {
				message = "split hostname: use separate hostnames"
			} else if len(containers) == 1 {
				key := parseNamespacedName(containers[0])
				compiled := statuses.AccessApplications[key]
				compiled.Bypass = appendUniqueBypass(compiled.Bypass, AccessBypass{Hostname: host.Hostname, Path: q.path})
				statuses.AccessApplications[key] = compiled
			}
		}
		if message != "" {
			key := types.NamespacedName{Namespace: route.Source.Namespace, Name: route.Source.Name}
			dropped[key] = append(dropped[key], routeRuleLabel(route)+" "+message)
			remaining[key]--
			continue
		}
		keptPublic = append(keptPublic, sanitizeUnprotectedRoute(route))
		publicIngress = append(publicIngress, accessRegionsToMatches([]accessRegion{q})...)
	}

	if len(keptPublic) > 0 {
		publicDomain := base
		publicDomain.Name = base.Name + "-public"
		publicDomain.Protected = false
		publicDomain.Access = nil
		publicDomain.AccessApplication = ""
		publicDomain.Guard = ir.GuardUnprotected
		publicDomain.StripAccessHeaders = true
		publicDomain.IngressPaths = publicIngress
		publicDomain.VirtualHosts = []ir.VirtualHost{{Name: host.Name + "-public", Hostname: host.Hostname, Routes: keptPublic}}
		gateway.Domains = append(gateway.Domains, publicDomain)
	} else if !publicAllowed && !accessRegionsCoverWholeHost(protectedRegions) {
		blocked := base
		blocked.Name = base.Name + "-blocked"
		blocked.Protected = false
		blocked.Access = nil
		blocked.Guard = ir.GuardBlocked
		blocked.StripAccessHeaders = true
		blocked.VirtualHosts = []ir.VirtualHost{{Name: host.Name + "-blocked", Hostname: host.Hostname}}
		gateway.Domains = append(gateway.Domains, blocked)
	}

	owners := make([]string, 0, len(regions))
	for owner := range regions {
		owners = append(owners, owner)
	}
	slices.Sort(owners)
	for _, owner := range owners {
		key := parseNamespacedName(owner)
		compilation := statuses.AccessApplications[key]
		if !compilation.Accepted {
			continue
		}
		protected := base
		protected.Name = base.Name + "-access-" + strings.ReplaceAll(owner, "/", "-")
		if listener := listenerByName(gateway.Listeners, base.ListenerName); listener != nil && listener.Exposure == ir.ExposurePrivate {
			protected.EnvoyPort = listener.Port
		} else {
			protected.EnvoyPort = *nextPublicPort
			(*nextPublicPort)++
		}
		protected.Protected = true
		protected.AccessApplication = owner
		protected.StripAccessHeaders = false
		protected.IngressPaths = accessRegionsToMatches(regions[owner])
		protected.VirtualHosts = []ir.VirtualHost{{Name: host.Name + "-access-" + strings.ReplaceAll(owner, "/", "-"), Hostname: host.Hostname, Routes: claimed[owner]}}
		application := accessApplicationByKey(in.AccessApplications, key)
		mode := v1alpha1.AccessOriginJWTModeRequired
		if application != nil {
			mode = effectiveOriginJWTMode(application)
		}
		switch mode {
		case v1alpha1.AccessOriginJWTModeDisabled:
			protected.OriginJWTDisabled = true
			protected.Access = nil
			if accessApplicationReady(in, key) {
				protected.Guard = ir.GuardForwarding
			} else {
				protected.Guard = ir.GuardBlocked
			}
		default:
			audiences, ready := accessAudiencesForDomain(in, statuses, key, base.ListenerName, host.Hostname)
			if ready && in.CloudflareAccount != nil &&
				in.CloudflareAccount.Status.Verified.TeamName != "" && in.CloudflareAccount.Status.Verified.AuthDomain != "" {
				protected.Access = &ir.AccessGuard{
					AUDs: audiences, TeamName: in.CloudflareAccount.Status.Verified.TeamName, AuthDomain: in.CloudflareAccount.Status.Verified.AuthDomain,
				}
				if application != nil && application.Spec.Application.OptionsPreflightBypass != nil {
					protected.Access.OptionsPreflightBypass = *application.Spec.Application.OptionsPreflightBypass
				}
				protected.Guard = ir.GuardForwarding
			} else {
				protected.Access = nil
				protected.Guard = ir.GuardBlocked
			}
		}
		gateway.Domains = append(gateway.Domains, protected)
		compilation.DataPlanes = append(compilation.DataPlanes, AccessDataPlane{
			Tunnel: func() string {
				if in.CloudflareTunnel == nil {
					return ""
				}
				return in.CloudflareTunnel.Name
			}(),
			Listener: base.ListenerName, ProtectionDomain: protected.Name, EnvoyPort: protected.EnvoyPort,
		})
		statuses.AccessApplications[key] = compilation
	}
}

func accessApplicationReady(in Inputs, applicationKey types.NamespacedName) bool {
	handoff := in.AUDSecrets[applicationKey]
	return handoff.Ready && handoff.ApplicationID != ""
}

func accessAudiencesForDomain(in Inputs, statuses *Statuses, applicationKey types.NamespacedName, listener, hostname string) ([]string, bool) {
	application := accessApplicationByKey(in.AccessApplications, applicationKey)
	if application == nil || effectiveOriginJWTAudienceScope(application) == v1alpha1.AccessOriginJWTAudienceScopeApplication {
		handoff := in.AUDSecrets[applicationKey]
		if !accessApplicationReady(in, applicationKey) || handoff.AUD == "" {
			return nil, false
		}
		return []string{handoff.AUD}, true
	}
	audiences := make([]string, 0)
	for key, compilation := range statuses.AccessApplications {
		if !compilation.Accepted || !compilationClaimsHostname(compilation, listener, hostname) {
			continue
		}
		handoff := in.AUDSecrets[key]
		if !accessApplicationReady(in, key) || handoff.AUD == "" {
			return nil, false
		}
		audiences = append(audiences, handoff.AUD)
	}
	slices.Sort(audiences)
	audiences = slices.Compact(audiences)
	return audiences, len(audiences) > 0
}

func compilationClaimsHostname(compilation AccessApplicationCompilation, listener, hostname string) bool {
	for _, claim := range compilation.claims {
		if claim.listener == listener && claim.hostname == hostname {
			return true
		}
	}
	return false
}

var reservedAccessHeaders = []string{
	"cf-access-jwt-assertion",
	"cf-access-authenticated-user-email",
	"cf-access-authenticated-user-id",
	"cf-access-authenticated-user-name",
	"cf-access-device-posture",
	"cf-access-client-id",
	"cf-access-client-secret",
}

func sanitizeUnprotectedRoute(route ir.Route) ir.Route {
	route.Filters.RequestHeaders = sanitizeAccessHeaderModifier(route.Filters.RequestHeaders)
	route.Backends = slices.Clone(route.Backends)
	for index := range route.Backends {
		route.Backends[index].Filters.RequestHeaders = sanitizeAccessHeaderModifier(route.Backends[index].Filters.RequestHeaders)
	}
	return route
}

func sanitizeAccessHeaderModifier(modifier *ir.HeaderModifier) *ir.HeaderModifier {
	if modifier == nil {
		return nil
	}
	out := &ir.HeaderModifier{Remove: slices.Clone(modifier.Remove)}
	for _, value := range modifier.Set {
		if !strings.HasPrefix(strings.ToLower(value.Name), "cf-access-") {
			out.Set = append(out.Set, value)
		}
	}
	for _, value := range modifier.Add {
		if !strings.HasPrefix(strings.ToLower(value.Name), "cf-access-") {
			out.Add = append(out.Add, value)
		}
	}
	for _, header := range reservedAccessHeaders {
		present := false
		for _, removed := range out.Remove {
			if strings.EqualFold(removed, header) {
				present = true
				break
			}
		}
		if !present {
			out.Remove = append(out.Remove, header)
		}
	}
	slices.Sort(out.Remove)
	return out
}

func markPublicDomainsForHeaderStripping(gateway *ir.Gateway) {
	if gateway == nil || gateway.ConformanceMode {
		return
	}
	for index := range gateway.Domains {
		domain := &gateway.Domains[index]
		if domain.Protected || domain.Guard != ir.GuardUnprotected {
			continue
		}
		domain.StripAccessHeaders = true
		for hostIndex := range domain.VirtualHosts {
			for routeIndex := range domain.VirtualHosts[hostIndex].Routes {
				domain.VirtualHosts[hostIndex].Routes[routeIndex] = sanitizeUnprotectedRoute(domain.VirtualHosts[hostIndex].Routes[routeIndex])
			}
		}
	}
}

func applyAccessRouteDrops(statuses *Statuses, in Inputs, dropped map[types.NamespacedName][]string, remaining map[types.NamespacedName]int, now metav1.Time) {
	for key, messages := range dropped {
		routeStatus, exists := statuses.HTTPRoutes[key]
		if !exists {
			continue
		}
		generation := int64(0)
		for index := range in.HTTPRoutes {
			if in.HTTPRoutes[index].Namespace == key.Namespace && in.HTTPRoutes[index].Name == key.Name {
				generation = in.HTTPRoutes[index].Generation
				break
			}
		}
		for index := range routeStatus.Parents {
			parent := &routeStatus.Parents[index]
			if parent.ControllerName != ControllerName {
				continue
			}
			if remaining[key] <= 0 {
				parent.Conditions = gatewaystatus.SetCondition(parent.Conditions, now, gatewaystatus.NewCondition(
					string(gatewayv1.RouteConditionAccepted), metav1.ConditionFalse, string(gatewayv1.RouteReasonUnsupportedValue), "all Route rules were dropped", generation, now,
				))
			}
			parent.Conditions = gatewaystatus.SetCondition(parent.Conditions, now, gatewaystatus.NewCondition(
				string(gatewayv1.RouteConditionPartiallyInvalid), metav1.ConditionTrue, string(gatewayv1.RouteReasonUnsupportedValue), "Dropped Rule: "+strings.Join(uniqueStrings(messages), "; "), generation, now,
			))
		}
		statuses.HTTPRoutes[key] = routeStatus
	}
}

func accessRegionForRoute(route ir.Route) (accessRegion, error) {
	if route.Match.Type == ir.PathMatchRegularExpression || !route.Source.PathExplicit && (route.Method != nil || len(route.Headers) > 0 || len(route.Query) > 0) {
		return accessRegion{kind: accessRegionPrefix, path: "/"}, nil
	}
	normalized, err := normalizeAccessPath(route.Match.Value)
	if err != nil {
		return accessRegion{}, fmt.Errorf("normalize route %s path: %w", route.Name, err)
	}
	if route.Match.Type == ir.PathMatchExact {
		return accessRegion{kind: accessRegionExact, path: normalized}, nil
	}
	if route.Match.Type == ir.PathMatchPathPrefix {
		return accessRegion{kind: accessRegionPrefix, path: normalized}, nil
	}
	return accessRegion{}, fmt.Errorf("route %s uses unsupported access path match %q", route.Name, route.Match.Type)
}

func normalizeAccessPath(value string) (string, error) {
	if value == "" {
		return "/", nil
	}
	decoded, err := url.PathUnescape(value)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(decoded, "/") {
		decoded = "/" + decoded
	}

	normalized := pathpkg.Clean(decoded)
	if normalized == "." || normalized == "" {
		return "/", nil
	}
	return normalized, nil
}
func accessClaimSpecificity(compilation AccessApplicationCompilation, listener, hostname string, region accessRegion) int {
	best := -1
	for _, claim := range compilation.claims {
		if claim.listener == listener && claim.hostname == hostname && claim.region == region && claim.specificity > best {
			best = claim.specificity
		}
	}
	return best
}

func accessRegionsOverlap(left, right accessRegion) bool {
	return accessRegionContains(left, right) || accessRegionContains(right, left)
}

func accessRegionContains(container, candidate accessRegion) bool {
	if container.kind == accessRegionExact {
		return candidate.kind == accessRegionExact && container.path == candidate.path
	}
	if container.path == "/" {
		return true
	}
	if candidate.path == container.path {
		return true
	}
	return strings.HasPrefix(candidate.path, container.path+"/")
}

func accessRegionsCoverWholeHost(regions map[string][]accessRegion) bool {
	for _, ownerRegions := range regions {
		for _, region := range ownerRegions {
			if region.kind == accessRegionPrefix && region.path == "/" {
				return true
			}
		}
	}
	return false
}

func appendAccessDestination(result *AccessApplicationCompilation, seen map[string]struct{}, in Inputs, gateway *ir.Gateway, listenerName, hostname string, region accessRegion) error {
	hostname = strings.ToLower(strings.TrimSuffix(hostname, "."))
	if listener := listenerByName(gateway.Listeners, listenerName); listener != nil && listener.Exposure == ir.ExposurePrivate {
		vnetID := privateListenerVNetID(in, listenerName)
		if vnetID == "" {
			return fmt.Errorf("private listener %q has no ready VirtualNetwork", listenerName)
		}
		protocol := v1alpha1.AccessL4ProtocolTCP
		appendCompiledDestination(result, seen, AccessDestination{
			Type: v1alpha1.AccessApplicationDestinationPrivate, Hostname: hostname, PortRange: fmt.Sprint(listener.Port),
			L4Protocol: &protocol, VNetID: vnetID,
		})
		return nil
	}
	uri := hostname
	if region.path != "" && region.path != "/" {
		uri += region.path
	}
	appendCompiledDestination(result, seen, AccessDestination{Type: v1alpha1.AccessApplicationDestinationPublic, URI: uri})
	return nil
}
func appendCompiledDestination(result *AccessApplicationCompilation, seen map[string]struct{}, destination AccessDestination) {
	key := accessDestinationKey(destination)
	if _, exists := seen[key]; exists {
		return
	}
	seen[key] = struct{}{}
	result.Destinations = append(result.Destinations, destination)
}

func accessDestinationKey(destination AccessDestination) string {
	protocol := ""
	if destination.L4Protocol != nil {
		protocol = string(*destination.L4Protocol)
	}
	return strings.Join([]string{
		string(destination.Type), destination.URI, destination.Hostname, destination.CIDR, destination.PortRange,
		protocol, destination.VNetID, destination.MCPServerID, destination.WorkerID,
	}, "\x00")
}
func appendAccessClaim(result *AccessApplicationCompilation, seen map[string]struct{}, claim accessClaim) {
	claim.hostname = strings.ToLower(strings.TrimSuffix(claim.hostname, "."))
	key := strings.Join([]string{claim.listener, claim.hostname, claim.routeName, claim.region.kind, claim.region.path, fmt.Sprint(claim.wholeHost), fmt.Sprint(claim.shadow)}, "\x00")
	if _, exists := seen[key]; exists {
		return
	}
	seen[key] = struct{}{}
	result.claims = append(result.claims, claim)
}

func appendAccessAncestor(result *AccessApplicationCompilation, seen map[string]struct{}, ancestor AccessAncestor) {
	key := strings.Join([]string{ancestor.Group, ancestor.Kind, ancestor.Namespace, ancestor.Name}, "\x00")
	if _, exists := seen[key]; exists {
		return
	}
	seen[key] = struct{}{}
	result.Ancestors = append(result.Ancestors, ancestor)
}

func appendUniqueAccessRegion(regions []accessRegion, candidate accessRegion) []accessRegion {
	for _, region := range regions {
		if region == candidate {
			return regions
		}
	}
	return append(regions, candidate)
}

func appendUniqueBypass(values []AccessBypass, candidate AccessBypass) []AccessBypass {
	for _, value := range values {
		if value == candidate {
			return values
		}
	}
	return append(values, candidate)
}

func rejectedAccessCompilation(compilation AccessApplicationCompilation, reason, message string) AccessApplicationCompilation {
	compilation.Accepted = false
	compilation.Reason = reason
	compilation.Message = message
	compilation.claims = nil
	return compilation
}

func accessFailure(reason, message string) AccessApplicationCompilation {
	return AccessApplicationCompilation{Accepted: false, Reason: reason, Message: message}
}

func accessRegionsToMatches(regions []accessRegion) []ir.PathMatch {
	result := make([]ir.PathMatch, 0, len(regions))
	for _, region := range regions {
		matchType := ir.PathMatchPathPrefix
		if region.kind == accessRegionExact {
			matchType = ir.PathMatchExact
		}
		result = append(result, ir.PathMatch{Type: matchType, Value: region.path})
	}
	return result
}

func nextAccessEnvoyPort(domains []ir.ProtectionDomain) int32 {
	nextPublic := int32(18080)
	for _, domain := range domains {
		if domain.EnvoyPort >= nextPublic {
			nextPublic = domain.EnvoyPort + 1
		}
	}
	return nextPublic
}

func effectiveOriginJWTMode(application *v1alpha1.AccessApplication) v1alpha1.AccessOriginJWTMode {
	if application.Spec.OriginJWT.Mode == "" {
		return v1alpha1.AccessOriginJWTModeRequired
	}
	return application.Spec.OriginJWT.Mode
}

func effectiveOriginJWTAudienceScope(application *v1alpha1.AccessApplication) v1alpha1.AccessOriginJWTAudienceScope {
	if application.Spec.OriginJWT.AudienceScope == "" {
		return v1alpha1.AccessOriginJWTAudienceScopeApplication
	}
	return application.Spec.OriginJWT.AudienceScope
}

func accessApplicationByKey(applications []v1alpha1.AccessApplication, key types.NamespacedName) *v1alpha1.AccessApplication {
	for index := range applications {
		if applications[index].Namespace == key.Namespace && applications[index].Name == key.Name {
			return &applications[index]
		}
	}
	return nil
}

func parseNamespacedName(value string) types.NamespacedName {
	namespace, name, _ := strings.Cut(value, "/")
	return types.NamespacedName{Namespace: namespace, Name: name}
}

func routeRuleLabel(route ir.Route) string {
	if route.Source.RuleName != "" {
		return fmt.Sprintf("rule %q", route.Source.RuleName)
	}
	return fmt.Sprintf("rule %d", route.Source.RuleIndex)
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func sortAccessCompilation(result *AccessApplicationCompilation) {
	result.Destinations = minimizeAccessDestinations(result.Destinations)
	slices.SortFunc(result.Destinations, func(left, right AccessDestination) int {
		return strings.Compare(accessDestinationKey(left), accessDestinationKey(right))
	})
	result.Destinations = compactAccessDestinations(result.Destinations)
	slices.SortFunc(result.DataPlanes, func(left, right AccessDataPlane) int {
		return strings.Compare(strings.Join([]string{left.Tunnel, left.Listener, left.ProtectionDomain, fmt.Sprint(left.EnvoyPort)}, "\x00"), strings.Join([]string{right.Tunnel, right.Listener, right.ProtectionDomain, fmt.Sprint(right.EnvoyPort)}, "\x00"))
	})
	slices.SortFunc(result.Bypass, func(left, right AccessBypass) int {
		return strings.Compare(left.Hostname+"\x00"+left.Path, right.Hostname+"\x00"+right.Path)
	})
	slices.SortFunc(result.Ancestors, func(left, right AccessAncestor) int {
		return strings.Compare(strings.Join([]string{left.Group, left.Kind, left.Namespace, left.Name}, "\x00"), strings.Join([]string{right.Group, right.Kind, right.Namespace, right.Name}, "\x00"))
	})
}

func compactAccessDestinations(values []AccessDestination) []AccessDestination {
	if len(values) < 2 {
		return values
	}
	result := values[:0]
	lastKey := ""
	for index, value := range values {
		key := accessDestinationKey(value)
		if index == 0 || key != lastKey {
			result = append(result, value)
			lastKey = key
		}
	}
	return result
}

func minimizeAccessDestinations(destinations []AccessDestination) []AccessDestination {
	public := make([]AccessDestination, 0, len(destinations))
	result := make([]AccessDestination, 0, len(destinations))
	for _, destination := range destinations {
		if destination.Type == v1alpha1.AccessApplicationDestinationPublic {
			public = append(public, destination)
		} else {
			result = append(result, destination)
		}
	}
	slices.SortFunc(public, func(left, right AccessDestination) int {
		if len(left.URI) != len(right.URI) {
			return len(left.URI) - len(right.URI)
		}
		return strings.Compare(left.URI, right.URI)
	})
	for _, candidate := range public {
		covered := false
		for _, existing := range result {
			if existing.Type == v1alpha1.AccessApplicationDestinationPublic && accessURIContains(existing.URI, candidate.URI) {
				covered = true
				break
			}
		}
		if !covered {
			result = append(result, candidate)
		}
	}
	return result
}

func accessURIContains(container, candidate string) bool {
	containerHost, containerPath, _ := strings.Cut(container, "/")
	candidateHost, candidatePath, _ := strings.Cut(candidate, "/")
	if containerHost != candidateHost {
		return false
	}
	containerPath = strings.Trim(containerPath, "/")
	candidatePath = strings.Trim(candidatePath, "/")
	if containerPath == "" {
		return true
	}
	return candidatePath == containerPath || strings.HasPrefix(candidatePath, containerPath+"/")
}
