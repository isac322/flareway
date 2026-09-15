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
	"time"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/isac322/flareway/internal/ir"
)

func compileRules(in Inputs, route *gatewayv1.HTTPRoute) ([]compiledRoute, gatewayv1.RouteConditionReason, string, []string, gatewayv1.RouteConditionReason) {
	compiled := make([]compiledRoute, 0)
	resolvedReason := gatewayv1.RouteReasonResolvedRefs
	resolvedMessage := "references resolved"
	dropped := make([]string, 0)
	dropReason := gatewayv1.RouteReasonUnsupportedValue

	for ruleIndex := range route.Spec.Rules {
		rule := &route.Spec.Rules[ruleIndex]
		ruleID := fmt.Sprintf("rule %d", ruleIndex)
		if rule.Name != nil {
			ruleID = fmt.Sprintf("rule %q", *rule.Name)
		}
		if rule.Retry != nil {
			dropped = append(dropped, ruleID+" uses unsupported retry")
			continue
		}
		if rule.SessionPersistence != nil {
			dropped = append(dropped, ruleID+" uses unsupported sessionPersistence")
			continue
		}

		filters, filterInvalid, filterReason, filterMessage := compileFilters(in, route, rule.Filters)
		if filterInvalid != nil && filterInvalid.Code != string(gatewayv1.RouteReasonInvalidKind) {
			dropped = append(dropped, ruleID+" "+filterInvalid.Message)
			if filterInvalid.Code == string(gatewayv1.RouteReasonIncompatibleFilters) {
				dropReason = gatewayv1.RouteReasonIncompatibleFilters
			}
			continue
		}
		if filterReason != gatewayv1.RouteReasonResolvedRefs && resolvedReason == gatewayv1.RouteReasonResolvedRefs {
			resolvedReason = filterReason
			resolvedMessage = filterMessage
		}

		backends := make([]ir.BackendRef, 0, len(rule.BackendRefs))
		for backendIndex := range rule.BackendRefs {
			backend, reason, message := compileHTTPBackendRef(in, route, rule.BackendRefs[backendIndex])
			backends = append(backends, backend)
			if reason != gatewayv1.RouteReasonResolvedRefs && resolvedReason == gatewayv1.RouteReasonResolvedRefs {
				resolvedReason = reason
				resolvedMessage = message
			}
		}

		if len(backends) == 0 && len(rule.Filters) == 0 && filterInvalid == nil {
			filterInvalid = &ir.Reason{Code: string(gatewayv1.RouteReasonBackendNotFound), Message: "rule has no backendRefs or terminal filter"}
		}

		matches := rule.Matches
		if len(matches) == 0 {
			matches = []gatewayv1.HTTPRouteMatch{{}}
		}
		for matchIndex := range matches {
			match, reason := compileMatch(matches[matchIndex])
			if reason != nil {
				dropped = append(dropped, ruleID+" "+reason.Message)
				continue
			}
			name := route.Namespace + "/" + route.Name + "/" + fmt.Sprint(ruleIndex) + "/" + fmt.Sprint(matchIndex)
			if rule.Name != nil {
				name = route.Namespace + "/" + route.Name + "/" + string(*rule.Name) + "/" + fmt.Sprint(matchIndex)
			}
			compiled = append(compiled, compiledRoute{
				route: ir.Route{
					Name: name,
					Source: ir.RouteSource{
						Namespace:    route.Namespace,
						Name:         route.Name,
						RuleIndex:    ruleIndex,
						MatchIndex:   matchIndex,
						PathExplicit: matches[matchIndex].Path != nil,
						RuleName: func() string {
							if rule.Name == nil {
								return ""
							}
							return string(*rule.Name)
						}(),
					},
					Match:    match.path,
					Headers:  match.headers,
					Query:    match.query,
					Method:   match.method,
					Filters:  filters,
					Backends: slices.Clone(backends),
					Timeouts: compileTimeouts(rule.Timeouts),
					Invalid:  filterInvalid,
				},
				creation:   route.CreationTimestamp,
				objectKey:  route.Namespace + "/" + route.Name,
				ruleIndex:  ruleIndex,
				matchIndex: matchIndex,
			})
		}
	}
	return compiled, resolvedReason, resolvedMessage, dropped, dropReason
}

type compiledMatch struct {
	path    ir.PathMatch
	headers []ir.HeaderMatch
	query   []ir.QueryMatch
	method  *string
}

func compileMatch(match gatewayv1.HTTPRouteMatch) (compiledMatch, *ir.Reason) {
	result := compiledMatch{path: ir.PathMatch{Type: ir.PathMatchPathPrefix, Value: "/"}}
	if match.Path != nil {
		pathType := gatewayv1.PathMatchPathPrefix
		if match.Path.Type != nil {
			pathType = *match.Path.Type
		}
		value := "/"
		if match.Path.Value != nil {
			value = *match.Path.Value
		}
		if pathType == gatewayv1.PathMatchPathPrefix && value != "/" {
			value = strings.TrimRight(value, "/")
			if value == "" {
				value = "/"
			}
		}
		switch pathType {
		case gatewayv1.PathMatchExact, gatewayv1.PathMatchPathPrefix, gatewayv1.PathMatchRegularExpression:
			result.path = ir.PathMatch{Type: string(pathType), Value: value}
		default:
			return result, &ir.Reason{Code: string(gatewayv1.RouteReasonUnsupportedValue), Message: fmt.Sprintf("uses unsupported path match type %q", pathType)}
		}
	}
	seenHeaders := make(map[string]struct{}, len(match.Headers))
	for _, header := range match.Headers {
		name := strings.ToLower(string(header.Name))
		if _, found := seenHeaders[name]; found {
			continue
		}
		seenHeaders[name] = struct{}{}
		matchType := gatewayv1.HeaderMatchExact
		if header.Type != nil {
			matchType = *header.Type
		}
		if matchType != gatewayv1.HeaderMatchExact && matchType != gatewayv1.HeaderMatchRegularExpression {
			return result, &ir.Reason{Code: string(gatewayv1.RouteReasonUnsupportedValue), Message: fmt.Sprintf("uses unsupported header match type %q", matchType)}
		}
		result.headers = append(result.headers, ir.HeaderMatch{Name: name, Type: string(matchType), Value: header.Value})
	}
	seenQuery := make(map[string]struct{}, len(match.QueryParams))
	for _, query := range match.QueryParams {
		name := string(query.Name)
		if _, found := seenQuery[name]; found {
			continue
		}
		seenQuery[name] = struct{}{}
		matchType := gatewayv1.QueryParamMatchExact
		if query.Type != nil {
			matchType = *query.Type
		}
		if matchType != gatewayv1.QueryParamMatchExact && matchType != gatewayv1.QueryParamMatchRegularExpression {
			return result, &ir.Reason{Code: string(gatewayv1.RouteReasonUnsupportedValue), Message: fmt.Sprintf("uses unsupported query match type %q", matchType)}
		}
		result.query = append(result.query, ir.QueryMatch{Name: name, Type: string(matchType), Value: query.Value})
	}
	slices.SortFunc(result.headers, func(a, b ir.HeaderMatch) int {
		if cmp := strings.Compare(a.Name, b.Name); cmp != 0 {
			return cmp
		}
		if cmp := strings.Compare(a.Type, b.Type); cmp != 0 {
			return cmp
		}
		return strings.Compare(a.Value, b.Value)
	})
	slices.SortFunc(result.query, func(a, b ir.QueryMatch) int {
		if cmp := strings.Compare(a.Name, b.Name); cmp != 0 {
			return cmp
		}
		if cmp := strings.Compare(a.Type, b.Type); cmp != 0 {
			return cmp
		}
		return strings.Compare(a.Value, b.Value)
	})
	if match.Method != nil {
		method := string(*match.Method)
		result.method = &method
	}
	return result, nil
}

func compileFilters(in Inputs, route *gatewayv1.HTTPRoute, filters []gatewayv1.HTTPRouteFilter) (ir.Filters, *ir.Reason, gatewayv1.RouteConditionReason, string) {
	result := ir.Filters{}
	resolvedReason := gatewayv1.RouteReasonResolvedRefs
	resolvedMessage := "references resolved"
	hasRedirect := false
	hasRewrite := false
	for _, filter := range filters {
		switch filter.Type {
		case gatewayv1.HTTPRouteFilterRequestHeaderModifier:
			if filter.RequestHeaderModifier == nil {
				return result, unsupportedFilter("RequestHeaderModifier has no configuration"), resolvedReason, resolvedMessage
			}
			result.RequestHeaders = compileHeaderModifier(*filter.RequestHeaderModifier)
		case gatewayv1.HTTPRouteFilterResponseHeaderModifier:
			if filter.ResponseHeaderModifier == nil {
				return result, unsupportedFilter("ResponseHeaderModifier has no configuration"), resolvedReason, resolvedMessage
			}
			result.ResponseHeaders = compileHeaderModifier(*filter.ResponseHeaderModifier)
		case gatewayv1.HTTPRouteFilterRequestRedirect:
			hasRedirect = true
			if filter.RequestRedirect == nil {
				return result, unsupportedFilter("RequestRedirect has no configuration"), resolvedReason, resolvedMessage
			}
			result.Redirect = compileRedirect(*filter.RequestRedirect)
		case gatewayv1.HTTPRouteFilterURLRewrite:
			hasRewrite = true
			if filter.URLRewrite == nil {
				return result, unsupportedFilter("URLRewrite has no configuration"), resolvedReason, resolvedMessage
			}
			result.URLRewrite = compileURLRewrite(*filter.URLRewrite)
		case gatewayv1.HTTPRouteFilterRequestMirror:
			if filter.RequestMirror == nil {
				return result, unsupportedFilter("RequestMirror has no configuration"), resolvedReason, resolvedMessage
			}
			backend, reason, message := compileBackendObjectRef(in, route, filter.RequestMirror.BackendRef, nil, nil)
			if backend.Invalid != nil {
				if resolvedReason == gatewayv1.RouteReasonResolvedRefs {
					resolvedReason, resolvedMessage = reason, message
				}
				continue
			}
			result.Mirrors = append(result.Mirrors, ir.Mirror{Backend: backend, Percent: mirrorPercent(*filter.RequestMirror)})
		case gatewayv1.HTTPRouteFilterCORS:
			if filter.CORS == nil {
				return result, unsupportedFilter("CORS has no configuration"), resolvedReason, resolvedMessage
			}
			result.CORS = compileCORS(*filter.CORS)
		case gatewayv1.HTTPRouteFilterExtensionRef:
			resolvedReason = gatewayv1.RouteReasonInvalidKind
			resolvedMessage = "ExtensionRef filters are not supported"
			return result, &ir.Reason{Code: string(gatewayv1.RouteReasonInvalidKind), Message: resolvedMessage}, resolvedReason, resolvedMessage
		default:
			return result, unsupportedFilter(fmt.Sprintf("uses unsupported filter type %q", filter.Type)), resolvedReason, resolvedMessage
		}
	}
	if hasRedirect && hasRewrite {
		return result, &ir.Reason{Code: string(gatewayv1.RouteReasonIncompatibleFilters), Message: "combines RequestRedirect and URLRewrite"}, resolvedReason, resolvedMessage
	}
	return result, nil, resolvedReason, resolvedMessage
}

func compileHeaderModifier(filter gatewayv1.HTTPHeaderFilter) *ir.HeaderModifier {
	result := &ir.HeaderModifier{}
	for _, header := range filter.Set {
		result.Set = append(result.Set, ir.HeaderValue{Name: strings.ToLower(string(header.Name)), Value: header.Value})
	}
	for _, header := range filter.Add {
		result.Add = append(result.Add, ir.HeaderValue{Name: strings.ToLower(string(header.Name)), Value: header.Value})
	}
	for _, header := range filter.Remove {
		result.Remove = append(result.Remove, strings.ToLower(header))
	}
	slices.SortFunc(result.Set, compareHeaderValues)
	slices.SortFunc(result.Add, compareHeaderValues)
	slices.Sort(result.Remove)
	return result
}

func compareHeaderValues(a, b ir.HeaderValue) int {
	if cmp := strings.Compare(a.Name, b.Name); cmp != 0 {
		return cmp
	}
	return strings.Compare(a.Value, b.Value)
}

func compileRedirect(filter gatewayv1.HTTPRequestRedirectFilter) *ir.Redirect {
	result := &ir.Redirect{StatusCode: 302}
	if filter.Scheme != nil {
		result.Scheme = *filter.Scheme
	}
	if filter.Hostname != nil {
		result.Hostname = string(*filter.Hostname)
	}
	if filter.Port != nil {
		result.Port = new(int32(*filter.Port))
	}
	if filter.StatusCode != nil {
		result.StatusCode = *filter.StatusCode
	}
	result.Path = compilePathModifier(filter.Path)
	return result
}

func compileURLRewrite(filter gatewayv1.HTTPURLRewriteFilter) *ir.URLRewrite {
	result := &ir.URLRewrite{}
	if filter.Hostname != nil {
		result.Hostname = string(*filter.Hostname)
	}
	result.Path = compilePathModifier(filter.Path)
	return result
}

func compilePathModifier(path *gatewayv1.HTTPPathModifier) *ir.PathModifier {
	if path == nil {
		return nil
	}
	result := &ir.PathModifier{Type: string(path.Type)}
	if path.ReplaceFullPath != nil {
		result.Replace = *path.ReplaceFullPath
	}
	if path.ReplacePrefixMatch != nil {
		result.Replace = *path.ReplacePrefixMatch
	}
	return result
}

func compileCORS(filter gatewayv1.HTTPCORSFilter) *ir.CORS {
	result := &ir.CORS{MaxAge: new(int32(5))}
	if filter.MaxAge > 0 {
		result.MaxAge = new(filter.MaxAge)
	}
	for _, value := range filter.AllowOrigins {
		result.AllowOrigins = append(result.AllowOrigins, string(value))
	}
	for _, value := range filter.AllowMethods {
		result.AllowMethods = append(result.AllowMethods, string(value))
	}
	for _, value := range filter.AllowHeaders {
		result.AllowHeaders = append(result.AllowHeaders, strings.ToLower(string(value)))
	}
	for _, value := range filter.ExposeHeaders {
		result.ExposeHeaders = append(result.ExposeHeaders, strings.ToLower(string(value)))
	}
	if filter.AllowCredentials != nil {
		result.AllowCredentials = *filter.AllowCredentials
	}
	slices.Sort(result.AllowOrigins)
	slices.Sort(result.AllowMethods)
	slices.Sort(result.AllowHeaders)
	slices.Sort(result.ExposeHeaders)
	return result
}

func mirrorPercent(filter gatewayv1.HTTPRequestMirrorFilter) float64 {
	if filter.Percent != nil {
		return float64(*filter.Percent)
	}
	if filter.Fraction != nil {
		denominator := int32(100)
		if filter.Fraction.Denominator != nil {
			denominator = *filter.Fraction.Denominator
		}
		return float64(filter.Fraction.Numerator) * 100 / float64(denominator)
	}
	return 100
}

func compileTimeouts(timeouts *gatewayv1.HTTPRouteTimeouts) ir.Timeouts {
	if timeouts == nil {
		return ir.Timeouts{}
	}
	return ir.Timeouts{
		Request:        parseDuration(timeouts.Request),
		BackendRequest: parseDuration(timeouts.BackendRequest),
	}
}

func parseDuration(value *gatewayv1.Duration) *time.Duration {
	if value == nil {
		return nil
	}
	duration, err := time.ParseDuration(string(*value))
	if err != nil {
		return nil
	}
	return new(duration)
}

func unsupportedFilter(message string) *ir.Reason {
	return &ir.Reason{Code: string(gatewayv1.RouteReasonUnsupportedValue), Message: message}
}
