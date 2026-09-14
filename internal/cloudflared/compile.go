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

// Package cloudflared compiles the deterministic Gateway IR into the complete
// remotely managed cloudflared configuration written to Cloudflare.
package cloudflared

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	cloudflare "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/zero_trust"

	"github.com/isac322/flareway/internal/ir"
)

const (
	originConnectTimeout       = int64(30)
	originKeepAliveTimeout     = int64(90)
	originKeepAliveConnections = int64(100)
)

// Compile returns the whole-object cloudflared configuration and the SHA-256
// hash of the JSON configuration body. AccountID is a path parameter and is not
// part of the hash.
func Compile(gateway *ir.Gateway) (zero_trust.TunnelCloudflaredConfigurationUpdateParams, string, error) {
	if gateway == nil {
		return zero_trust.TunnelCloudflaredConfigurationUpdateParams{}, "", errors.New("compile cloudflared configuration: Gateway is nil")
	}
	if gateway.Cloudflare == nil {
		return zero_trust.TunnelCloudflaredConfigurationUpdateParams{}, "", errors.New("compile cloudflared configuration: Cloudflare settings are absent")
	}
	if gateway.Cloudflare.AccountID == "" {
		return zero_trust.TunnelCloudflaredConfigurationUpdateParams{}, "", errors.New("compile cloudflared configuration: account ID is empty")
	}

	config := compileConfig(gateway)
	payload, err := json.Marshal(config)
	if err != nil {
		return zero_trust.TunnelCloudflaredConfigurationUpdateParams{}, "", fmt.Errorf("marshal cloudflared configuration: %w", err)
	}
	var rawConfig map[string]any
	if err := json.Unmarshal(payload, &rawConfig); err != nil {
		return zero_trust.TunnelCloudflaredConfigurationUpdateParams{}, "", fmt.Errorf("prepare cloudflared SDK payload: %w", err)
	}
	digest := sha256.Sum256(payload)

	return zero_trust.TunnelCloudflaredConfigurationUpdateParams{
		AccountID: cloudflare.F(gateway.Cloudflare.AccountID),
		// cloudflare-go v7.10.0 omits warp-routing from its generated Config
		// struct. Raw keeps the real SDK request type while preserving the API's
		// complete whole-object JSON contract.
		Config: cloudflare.Raw[zero_trust.TunnelCloudflaredConfigurationUpdateParamsConfig](rawConfig),
	}, hex.EncodeToString(digest[:]), nil
}

type configBody struct {
	Ingress       []ingressRule `json:"ingress"`
	OriginRequest originRequest `json:"originRequest"`
	WARPRouting   warpRouting   `json:"warp-routing"`
}

type ingressRule struct {
	Hostname      string         `json:"hostname,omitempty"`
	Path          string         `json:"path,omitempty"`
	Service       string         `json:"service"`
	OriginRequest *originRequest `json:"originRequest,omitempty"`
}

type originRequest struct {
	ConnectTimeout       int64   `json:"connectTimeout"`
	KeepAliveTimeout     int64   `json:"keepAliveTimeout"`
	KeepAliveConnections int64   `json:"keepAliveConnections"`
	NoHappyEyeballs      bool    `json:"noHappyEyeballs"`
	Access               *access `json:"access,omitempty"`
}

type access struct {
	Required bool     `json:"required"`
	TeamName string   `json:"teamName"`
	AUDTag   []string `json:"audTag"`
}

type warpRouting struct {
	Enabled bool `json:"enabled"`
}

type domainRule struct {
	category int
	order    int
	hostname string
	path     string
	service  string
	origin   *originRequest
}

func compileConfig(gateway *ir.Gateway) configBody {
	baseOrigin := originRequest{
		ConnectTimeout:       originConnectTimeout,
		KeepAliveTimeout:     originKeepAliveTimeout,
		KeepAliveConnections: originKeepAliveConnections,
		NoHappyEyeballs:      true,
	}

	listenerExposure := make(map[string]string, len(gateway.Listeners))
	warpEnabled := gateway.Cloudflare.WARPRouting
	for _, listener := range gateway.Listeners {
		listenerExposure[listener.Name] = listener.Exposure
		warpEnabled = warpEnabled || listener.Exposure == ir.ExposurePrivate
	}

	rules := make([]domainRule, 0, len(gateway.Domains))
	order := 0
	for _, domain := range gateway.Domains {
		if listenerExposure[domain.ListenerName] == ir.ExposurePrivate {
			continue
		}
		for _, virtualHost := range domain.VirtualHosts {
			hostname := virtualHost.Hostname
			if hostname == "" || hostname == "*" {
				continue
			}
			if gateway.Cloudflare.Teardown || domain.Guard == ir.GuardBlocked || (domain.Protected && domain.Access == nil && !domain.OriginJWTDisabled) {
				rules = append(rules, domainRule{category: 2, order: order, hostname: hostname, service: "http_status:403"})
				order++
				continue
			}

			origin := baseOrigin
			category := 0
			paths := []string{""}
			if len(domain.IngressPaths) > 0 {
				paths = forwardingMatchPaths(domain.IngressPaths)
			}
			if domain.Protected {
				category = 1
				if domain.Access != nil {
					origin.Access = &access{
						Required: true,
						TeamName: domain.Access.TeamName,
						AUDTag:   []string{domain.Access.AUD},
					}
				}
				if len(domain.IngressPaths) == 0 {
					paths = forwardingPaths(virtualHost.Routes)
				}
			}
			for _, path := range paths {
				rules = append(rules, domainRule{
					category: category,
					order:    order,
					hostname: hostname,
					path:     path,
					service:  fmt.Sprintf("http://127.0.0.1:%d", domain.EnvoyPort),
					origin:   cloneOrigin(origin),
				})
				order++
			}
		}
	}

	// Hostname specificity is the outer ordering boundary: an exact hostname
	// must always beat a wildcard, regardless of public/protected category.
	// Within one hostname, approved public carve-outs precede their enclosing
	// protected paths, and more-specific paths precede broader paths.
	slices.SortStableFunc(rules, func(a, b domainRule) int {
		if compared := compareIngressHostnames(a.hostname, b.hostname); compared != 0 {
			return compared
		}
		if a.category != b.category {
			return a.category - b.category
		}
		if len(a.path) != len(b.path) {
			return len(b.path) - len(a.path)
		}
		return a.order - b.order
	})

	ingress := make([]ingressRule, 0, len(rules)+1)
	seen := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		key := strings.Join([]string{rule.hostname, rule.path, rule.service}, "\x00")
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		ingress = append(ingress, ingressRule{
			Hostname:      rule.hostname,
			Path:          rule.path,
			Service:       rule.service,
			OriginRequest: rule.origin,
		})
	}
	ingress = append(ingress, ingressRule{Service: "http_status:404"})

	return configBody{Ingress: ingress, OriginRequest: baseOrigin, WARPRouting: warpRouting{Enabled: warpEnabled}}
}

func compareIngressHostnames(left, right string) int {
	leftWildcard := strings.HasPrefix(left, "*.")
	rightWildcard := strings.HasPrefix(right, "*.")
	if leftWildcard != rightWildcard {
		if leftWildcard {
			return 1
		}
		return -1
	}
	if len(left) != len(right) {
		return len(right) - len(left)
	}
	return strings.Compare(left, right)
}

func forwardingMatchPaths(matches []ir.PathMatch) []string {
	routes := make([]ir.Route, 0, len(matches))
	for _, match := range matches {
		routes = append(routes, ir.Route{Match: match})
	}
	return forwardingPaths(routes)
}

func forwardingPaths(routes []ir.Route) []string {
	if len(routes) == 0 {
		return []string{""}
	}
	paths := make([]string, 0, len(routes))
	for _, route := range routes {
		switch route.Match.Type {
		case ir.PathMatchExact:
			paths = append(paths, "^"+regexp.QuoteMeta(route.Match.Value)+"$")
		case ir.PathMatchRegularExpression:
			paths = append(paths, route.Match.Value)
		case ir.PathMatchPathPrefix:
			if route.Match.Value == "" || route.Match.Value == "/" {
				return []string{""}
			}
			paths = append(paths, "^"+regexp.QuoteMeta(strings.TrimRight(route.Match.Value, "/"))+"(/|$)")
		}
	}
	if len(paths) == 0 {
		return []string{""}
	}
	return unique(paths)
}

func unique(values []string) []string {
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

func cloneOrigin(in originRequest) *originRequest {
	out := in
	if in.Access != nil {
		copied := *in.Access
		copied.AUDTag = slices.Clone(in.Access.AUDTag)
		out.Access = &copied
	}
	return &out
}
