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

package translator

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	corsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/cors/v3"
	matcherv3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/isac322/flareway/internal/ir"
)

const corsFilterName = "envoy.filters.http.cors"

var accessIdentityHeaders = []string{
	"Cf-Access-Jwt-Assertion",
	"Cf-Access-Authenticated-User-Email",
	"Cf-Access-Authenticated-User-Id",
	"Cf-Access-Authenticated-User-Name",
	"Cf-Access-Device-Posture",
	"Cf-Access-Client-Id",
	"Cf-Access-Client-Secret",
}

func buildDomainVirtualHost(in ir.VirtualHost, guard string, stripAccessHeaders bool) (*routev3.VirtualHost, error) {
	if guard == ir.GuardBlocked {
		hostname := in.Hostname
		if hostname == "" {
			hostname = "*"
		}
		return &routev3.VirtualHost{
			Name:    resourceName(in.Name, "virtual-host"),
			Domains: []string{hostname},
			Routes: []*routev3.Route{{
				Name:  resourceName(in.Name+"-access-blocked", "access-blocked"),
				Match: &routev3.RouteMatch{PathSpecifier: &routev3.RouteMatch_Prefix{Prefix: "/"}},
				Action: &routev3.Route_DirectResponse{DirectResponse: &routev3.DirectResponseAction{
					Status: 403,
				}},
			}},
		}, nil
	}
	out, err := buildVirtualHost(in)
	if err != nil {
		return nil, err
	}
	if stripAccessHeaders {
		out.RequestHeadersToRemove = append(out.RequestHeadersToRemove, accessIdentityHeaders...)
	}
	return out, nil
}

func buildVirtualHost(in ir.VirtualHost) (*routev3.VirtualHost, error) {
	hostname := in.Hostname
	if hostname == "" {
		hostname = "*"
	}
	out := &routev3.VirtualHost{
		Name:    resourceName(in.Name, "virtual-host"),
		Domains: []string{hostname},
	}
	for _, route := range in.Routes {
		translated, err := buildRoutes(route)
		if err != nil {
			return nil, fmt.Errorf("translate route %q: %w", route.Name, err)
		}
		out.Routes = append(out.Routes, translated...)
	}
	out.Routes = append(out.Routes, &routev3.Route{
		Name:  out.Name + "-not-found",
		Match: &routev3.RouteMatch{PathSpecifier: &routev3.RouteMatch_Prefix{Prefix: "/"}},
		Action: &routev3.Route_DirectResponse{DirectResponse: &routev3.DirectResponseAction{
			Status: 404,
		}},
	})
	return out, nil
}

func buildRoutes(in ir.Route) ([]*routev3.Route, error) {
	match, err := buildRouteMatch(in)
	if err != nil {
		return nil, err
	}
	base := &routev3.Route{Name: resourceName(in.Name, "route"), Match: match}
	applyHeaderModifier(base, in.Filters.RequestHeaders, true)
	applyHeaderModifier(base, in.Filters.ResponseHeaders, false)
	if in.Filters.CORS != nil {
		cors, err := buildCORS(in.Filters.CORS)
		if err != nil {
			return nil, err
		}
		base.TypedPerFilterConfig = map[string]*anypb.Any{corsFilterName: cors}
	}
	if in.Invalid != nil {
		base.Action = directResponse(500)
		return []*routev3.Route{base}, nil
	}
	if in.Filters.Redirect != nil {
		redirect, err := buildRedirect(in.Filters.Redirect)
		if err != nil {
			return nil, err
		}
		base.Action = &routev3.Route_Redirect{Redirect: redirect}
		return []*routev3.Route{base}, nil
	}

	valid := make([]ir.BackendRef, 0, len(in.Backends))
	var validWeight, invalidWeight uint64
	for _, backend := range in.Backends {
		weight := backendWeight(backend.Weight)
		if weight == 0 {
			continue
		}
		if backend.Invalid != nil || backend.ClusterName == "" {
			invalidWeight += uint64(weight)
			continue
		}
		valid = append(valid, backend)
		validWeight += uint64(weight)
	}
	totalWeight := validWeight + invalidWeight
	if totalWeight == 0 || len(valid) == 0 {
		base.Action = directResponse(500)
		return []*routev3.Route{base}, nil
	}

	action, err := buildRouteAction(in, valid)
	if err != nil {
		return nil, err
	}
	base.Action = &routev3.Route_Route{Route: action}
	if invalidWeight == 0 {
		return []*routev3.Route{base}, nil
	}

	failure := proto.Clone(base).(*routev3.Route)
	failure.Name += "-invalid-backend"
	failure.Action = directResponse(500)
	failure.Match.RuntimeFraction = fractionalPercent(float64(invalidWeight) * 100 / float64(totalWeight))
	base.Name += "-valid-backend"
	return []*routev3.Route{failure, base}, nil
}

func buildRouteMatch(in ir.Route) (*routev3.RouteMatch, error) {
	out := &routev3.RouteMatch{CaseSensitive: wrapperspb.Bool(true)}
	switch in.Match.Type {
	case ir.PathMatchExact:
		out.PathSpecifier = &routev3.RouteMatch_Path{Path: in.Match.Value}
	case ir.PathMatchRegularExpression:
		out.PathSpecifier = &routev3.RouteMatch_SafeRegex{SafeRegex: regexMatcher(in.Match.Value)}
	case ir.PathMatchPathPrefix, "":
		if in.Match.Value == "" || in.Match.Value == "/" {
			out.PathSpecifier = &routev3.RouteMatch_Prefix{Prefix: "/"}
		} else {
			out.PathSpecifier = &routev3.RouteMatch_PathSeparatedPrefix{PathSeparatedPrefix: in.Match.Value}
		}
	default:
		return nil, fmt.Errorf("unsupported path match type %q", in.Match.Type)
	}
	if in.Method != nil {
		out.Headers = append(out.Headers, &routev3.HeaderMatcher{
			Name: ":method",
			HeaderMatchSpecifier: &routev3.HeaderMatcher_StringMatch{
				StringMatch: exactStringMatcher(*in.Method),
			},
		})
	}
	for _, header := range in.Headers {
		matcher, err := stringMatcher(header.Type, header.Value)
		if err != nil {
			return nil, fmt.Errorf("header %q: %w", header.Name, err)
		}
		out.Headers = append(out.Headers, &routev3.HeaderMatcher{
			Name: header.Name,
			HeaderMatchSpecifier: &routev3.HeaderMatcher_StringMatch{
				StringMatch: matcher,
			},
		})
	}
	for _, query := range in.Query {
		matcher, err := stringMatcher(query.Type, query.Value)
		if err != nil {
			return nil, fmt.Errorf("query parameter %q: %w", query.Name, err)
		}
		out.QueryParameters = append(out.QueryParameters, &routev3.QueryParameterMatcher{
			Name: query.Name,
			QueryParameterMatchSpecifier: &routev3.QueryParameterMatcher_StringMatch{
				StringMatch: matcher,
			},
		})
	}
	return out, nil
}

func buildRouteAction(in ir.Route, valid []ir.BackendRef) (*routev3.RouteAction, error) {
	if in.Filters.URLRewrite != nil {
		for _, backend := range valid {
			if backend.Filters.URLRewrite != nil {
				return nil, fmt.Errorf("rule and backend URLRewrite filters cannot be combined")
			}
		}
	}
	if len(valid) > 1 {
		for _, backend := range valid {
			if backend.Filters.URLRewrite != nil && backend.Filters.URLRewrite.Path != nil {
				return nil, fmt.Errorf("per-backend path rewrite requires a single backend")
			}
		}
	}
	weighted := &routev3.WeightedCluster{
		Clusters: make([]*routev3.WeightedCluster_ClusterWeight, 0, len(valid)),
	}
	for _, backend := range valid {
		cluster := &routev3.WeightedCluster_ClusterWeight{
			Name:   backend.ClusterName,
			Weight: wrapperspb.UInt32(backendWeight(backend.Weight)),
		}
		applyBackendHeaderModifier(cluster, backend.Filters.RequestHeaders, true)
		applyBackendHeaderModifier(cluster, backend.Filters.ResponseHeaders, false)
		if backend.Filters.URLRewrite != nil && backend.Filters.URLRewrite.Hostname != "" {
			cluster.HostRewriteSpecifier = &routev3.WeightedCluster_ClusterWeight_HostRewriteLiteral{
				HostRewriteLiteral: backend.Filters.URLRewrite.Hostname,
			}
		}
		weighted.Clusters = append(weighted.Clusters, cluster)
	}
	action := &routev3.RouteAction{
		ClusterSpecifier:      &routev3.RouteAction_WeightedClusters{WeightedClusters: weighted},
		RequestMirrorPolicies: buildMirrors(in.Filters.Mirrors),
	}
	applyTimeouts(action, in.Timeouts)
	if in.Filters.URLRewrite != nil {
		applyURLRewrite(action, in.Filters.URLRewrite, in.Match)
	} else if len(valid) == 1 && valid[0].Filters.URLRewrite != nil {
		applyURLRewrite(action, valid[0].Filters.URLRewrite, in.Match)
	}
	return action, nil
}

func buildRedirect(in *ir.Redirect) (*routev3.RedirectAction, error) {
	out := &routev3.RedirectAction{
		HostRedirect: in.Hostname,
		ResponseCode: redirectCode(in.StatusCode),
	}
	if in.Scheme != "" {
		out.SchemeRewriteSpecifier = &routev3.RedirectAction_SchemeRedirect{SchemeRedirect: in.Scheme}
	}
	if in.Port != nil {
		out.PortRedirect = uint32(*in.Port)
	}
	if in.Path != nil {
		switch in.Path.Type {
		case ir.PathModifierReplaceFullPath:
			out.PathRewriteSpecifier = &routev3.RedirectAction_PathRewrite{PathRewrite: in.Path.Replace}
		case ir.PathModifierReplacePrefixMatch:
			out.PathRewriteSpecifier = &routev3.RedirectAction_PrefixRewrite{PrefixRewrite: in.Path.Replace}
		default:
			return nil, fmt.Errorf("unsupported redirect path modifier %q", in.Path.Type)
		}
	}
	return out, nil
}

func applyURLRewrite(action *routev3.RouteAction, rewrite *ir.URLRewrite, match ir.PathMatch) {
	if rewrite == nil {
		return
	}
	if rewrite.Hostname != "" {
		action.HostRewriteSpecifier = &routev3.RouteAction_HostRewriteLiteral{HostRewriteLiteral: rewrite.Hostname}
	}
	if rewrite.Path == nil {
		return
	}
	switch rewrite.Path.Type {
	case ir.PathModifierReplaceFullPath:
		action.PathRewrite = rewrite.Path.Replace
	case ir.PathModifierReplacePrefixMatch:
		if match.Type == ir.PathMatchPathPrefix && match.Value != "/" && strings.HasSuffix(rewrite.Path.Replace, "/") {
			action.RegexRewrite = &matcherv3.RegexMatchAndSubstitute{
				Pattern:      regexMatcher("^" + regexp.QuoteMeta(match.Value) + "/?(.*)$"),
				Substitution: rewrite.Path.Replace + "\\1",
			}
			return
		}
		action.PrefixRewrite = rewrite.Path.Replace
	}
}

func buildMirrors(in []ir.Mirror) []*routev3.RouteAction_RequestMirrorPolicy {
	out := make([]*routev3.RouteAction_RequestMirrorPolicy, 0, len(in))
	for _, mirror := range in {
		if mirror.Backend.Invalid != nil || mirror.Backend.ClusterName == "" || mirror.Percent <= 0 {
			continue
		}
		percent := mirror.Percent
		if percent > 100 {
			percent = 100
		}
		out = append(out, &routev3.RouteAction_RequestMirrorPolicy{
			Cluster:         mirror.Backend.ClusterName,
			RuntimeFraction: fractionalPercent(percent),
		})
	}
	return out
}

func applyTimeouts(action *routev3.RouteAction, timeouts ir.Timeouts) {
	switch {
	case timeouts.Request != nil && timeouts.BackendRequest != nil:
		action.Timeout = durationpb.New(*timeouts.BackendRequest)
		action.MaxStreamDuration = &routev3.RouteAction_MaxStreamDuration{
			MaxStreamDuration: durationpb.New(*timeouts.Request),
		}
	case timeouts.Request != nil:
		action.Timeout = durationpb.New(*timeouts.Request)
		if *timeouts.Request == 0 {
			action.MaxStreamDuration = &routev3.RouteAction_MaxStreamDuration{
				MaxStreamDuration: durationpb.New(0),
			}
		}
	case timeouts.BackendRequest != nil:
		action.Timeout = durationpb.New(*timeouts.BackendRequest)
	}
	if (timeouts.Request != nil && *timeouts.Request == 0) ||
		(timeouts.BackendRequest != nil && *timeouts.BackendRequest == 0) {
		action.IdleTimeout = durationpb.New(0)
	}
}

func buildCORS(in *ir.CORS) (*anypb.Any, error) {
	policy := &corsv3.CorsPolicy{
		AllowMethods:                 strings.Join(in.AllowMethods, ","),
		AllowHeaders:                 strings.Join(in.AllowHeaders, ","),
		ExposeHeaders:                strings.Join(in.ExposeHeaders, ","),
		AllowCredentials:             wrapperspb.Bool(in.AllowCredentials),
		ForwardNotMatchingPreflights: wrapperspb.Bool(false),
	}
	for _, origin := range in.AllowOrigins {
		if strings.Contains(origin, "*") {
			policy.AllowOriginStringMatch = append(policy.AllowOriginStringMatch, &matcherv3.StringMatcher{
				MatchPattern: &matcherv3.StringMatcher_SafeRegex{SafeRegex: regexMatcher(globToRegex(origin))},
			})
		} else {
			policy.AllowOriginStringMatch = append(policy.AllowOriginStringMatch, exactStringMatcher(origin))
		}
	}
	if in.MaxAge != nil {
		policy.MaxAge = strconv.FormatInt(int64(*in.MaxAge), 10)
	}
	return anypb.New(policy)
}

func applyHeaderModifier(route *routev3.Route, modifier *ir.HeaderModifier, request bool) {
	if modifier == nil {
		return
	}
	set := headerOptions(modifier.Set, corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD)
	add := headerOptions(modifier.Add, corev3.HeaderValueOption_APPEND_IF_EXISTS_OR_ADD)
	if request {
		route.RequestHeadersToAdd = append(route.RequestHeadersToAdd, set...)
		route.RequestHeadersToAdd = append(route.RequestHeadersToAdd, add...)
		route.RequestHeadersToRemove = append(route.RequestHeadersToRemove, modifier.Remove...)
	} else {
		route.ResponseHeadersToAdd = append(route.ResponseHeadersToAdd, set...)
		route.ResponseHeadersToAdd = append(route.ResponseHeadersToAdd, add...)
		route.ResponseHeadersToRemove = append(route.ResponseHeadersToRemove, modifier.Remove...)
	}
}

func applyBackendHeaderModifier(cluster *routev3.WeightedCluster_ClusterWeight, modifier *ir.HeaderModifier, request bool) {
	if modifier == nil {
		return
	}
	set := headerOptions(modifier.Set, corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD)
	add := headerOptions(modifier.Add, corev3.HeaderValueOption_APPEND_IF_EXISTS_OR_ADD)
	if request {
		cluster.RequestHeadersToAdd = append(cluster.RequestHeadersToAdd, set...)
		cluster.RequestHeadersToAdd = append(cluster.RequestHeadersToAdd, add...)
		cluster.RequestHeadersToRemove = append(cluster.RequestHeadersToRemove, modifier.Remove...)
	} else {
		cluster.ResponseHeadersToAdd = append(cluster.ResponseHeadersToAdd, set...)
		cluster.ResponseHeadersToAdd = append(cluster.ResponseHeadersToAdd, add...)
		cluster.ResponseHeadersToRemove = append(cluster.ResponseHeadersToRemove, modifier.Remove...)
	}
}

func headerOptions(values []ir.HeaderValue, action corev3.HeaderValueOption_HeaderAppendAction) []*corev3.HeaderValueOption {
	out := make([]*corev3.HeaderValueOption, 0, len(values))
	for _, value := range values {
		out = append(out, &corev3.HeaderValueOption{
			Header:       &corev3.HeaderValue{Key: value.Name, Value: value.Value},
			AppendAction: action,
		})
	}
	return out
}

func stringMatcher(matchType, value string) (*matcherv3.StringMatcher, error) {
	switch matchType {
	case ir.StringMatchExact, "":
		return exactStringMatcher(value), nil
	case ir.StringMatchRegularExpression:
		return &matcherv3.StringMatcher{MatchPattern: &matcherv3.StringMatcher_SafeRegex{SafeRegex: regexMatcher(value)}}, nil
	default:
		return nil, fmt.Errorf("unsupported string match type %q", matchType)
	}
}

func exactStringMatcher(value string) *matcherv3.StringMatcher {
	return &matcherv3.StringMatcher{MatchPattern: &matcherv3.StringMatcher_Exact{Exact: value}}
}

func regexMatcher(value string) *matcherv3.RegexMatcher {
	return &matcherv3.RegexMatcher{Regex: value}
}

func fractionalPercent(percent float64) *corev3.RuntimeFractionalPercent {
	if percent < 0 {
		percent = 0
	}
	if percent > 100 {
		percent = 100
	}
	return &corev3.RuntimeFractionalPercent{DefaultValue: &typev3.FractionalPercent{
		Numerator:   uint32(math.Round(percent * 10_000)),
		Denominator: typev3.FractionalPercent_MILLION,
	}}
}

func backendWeight(weight int32) uint32 {
	if weight <= 0 {
		return 0
	}
	return uint32(weight)
}

func redirectCode(code int) routev3.RedirectAction_RedirectResponseCode {
	switch code {
	case 302:
		return routev3.RedirectAction_FOUND
	case 303:
		return routev3.RedirectAction_SEE_OTHER
	case 307:
		return routev3.RedirectAction_TEMPORARY_REDIRECT
	case 308:
		return routev3.RedirectAction_PERMANENT_REDIRECT
	default:
		return routev3.RedirectAction_MOVED_PERMANENTLY
	}
}

func directResponse(status uint32) *routev3.Route_DirectResponse {
	return &routev3.Route_DirectResponse{DirectResponse: &routev3.DirectResponseAction{Status: status}}
}

func globToRegex(value string) string {
	var out strings.Builder
	out.WriteByte('^')
	for _, char := range value {
		switch char {
		case '*':
			out.WriteString(".*")
		case '.', '+', '(', ')', '|', '{', '}', '[', ']', '?', '^', '$', '\\':
			out.WriteByte('\\')
			out.WriteRune(char)
		default:
			out.WriteRune(char)
		}
	}
	out.WriteByte('$')
	return out.String()
}
