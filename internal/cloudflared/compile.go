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

// Package cloudflared compiles deterministic Gateway and Direct tunnel IR into
// complete remotely managed cloudflared configurations written to Cloudflare.
package cloudflared

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	cloudflare "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/zero_trust"

	"github.com/isac322/flareway/internal/ir"
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
	if err := validateGatewayOriginRequest(gateway.Cloudflare.OriginRequest); err != nil {
		return zero_trust.TunnelCloudflaredConfigurationUpdateParams{}, "", err
	}
	return compileRequest(gateway.Cloudflare.AccountID, compileConfig(gateway))
}

// CompileDirect returns the whole-object cloudflared configuration for a
// Direct-mode CloudflareTunnel. It validates the ordered ingress program before
// constructing an SDK request, so an invalid catch-all or service never reaches
// the Cloudflare API.
func CompileDirect(accountID string, configuration ir.TunnelConfiguration) (zero_trust.TunnelCloudflaredConfigurationUpdateParams, string, error) {
	if accountID == "" {
		return zero_trust.TunnelCloudflaredConfigurationUpdateParams{}, "", errors.New("compile direct cloudflared configuration: account ID is empty")
	}
	config, err := compileDirectConfig(configuration)
	if err != nil {
		return zero_trust.TunnelCloudflaredConfigurationUpdateParams{}, "", err
	}
	return compileRequest(accountID, config)
}

func compileRequest(accountID string, config configBody) (zero_trust.TunnelCloudflaredConfigurationUpdateParams, string, error) {
	payload, err := json.Marshal(config)
	if err != nil {
		return zero_trust.TunnelCloudflaredConfigurationUpdateParams{}, "", fmt.Errorf("marshal cloudflared configuration: %w", err)
	}
	var rawConfig map[string]any
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	if err := decoder.Decode(&rawConfig); err != nil {
		return zero_trust.TunnelCloudflaredConfigurationUpdateParams{}, "", fmt.Errorf("prepare cloudflared SDK payload: %w", err)
	}
	digest := sha256.Sum256(payload)

	return zero_trust.TunnelCloudflaredConfigurationUpdateParams{
		AccountID: cloudflare.F(accountID),
		// cloudflare-go v7.10.0 omits fields accepted by the configuration API,
		// including warp-routing and parts of originRequest. Raw preserves the
		// real SDK request type and the complete whole-object JSON contract.
		Config: cloudflare.Raw[zero_trust.TunnelCloudflaredConfigurationUpdateParamsConfig](rawConfig),
	}, hex.EncodeToString(digest[:]), nil
}

func compileConfig(gateway *ir.Gateway) configBody {
	baseOrigin := gatewayOrigin(gateway.Cloudflare.OriginRequest)

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
		audiences := domain.Access.CanonicalAUDs()
		for _, virtualHost := range domain.VirtualHosts {
			hostname := virtualHost.Hostname
			if hostname == "" || hostname == "*" {
				continue
			}
			if gateway.Cloudflare.Teardown || domain.Guard == ir.GuardBlocked ||
				(domain.Protected && !domain.OriginJWTDisabled && len(audiences) == 0) {
				rules = append(rules, domainRule{category: 2, order: order, hostname: hostname, service: "http_status:403"})
				order++
				continue
			}

			origin := cloneOrigin(baseOrigin)
			category := 0
			paths := []string{""}
			if len(domain.IngressPaths) > 0 {
				paths = forwardingMatchPaths(domain.IngressPaths)
			}
			if domain.Protected {
				category = 1
				if len(audiences) > 0 {
					required := true
					origin.Access = &access{
						Required: &required,
						TeamName: domain.Access.TeamName,
						AUDTag:   audiences,
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

	warpEnabledValue := warpEnabled
	return configBody{
		Ingress:       ingress,
		OriginRequest: baseOrigin,
		WARPRouting:   &warpRouting{Enabled: &warpEnabledValue},
	}
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

func validateGatewayOriginRequest(origin ir.GatewayOriginRequest) error {
	for _, field := range []struct {
		name  string
		value *time.Duration
	}{
		{name: "connectTimeout", value: origin.ConnectTimeout},
		{name: "keepAliveTimeout", value: origin.KeepAliveTimeout},
		{name: "tcpKeepAlive", value: origin.TCPKeepAlive},
	} {
		if field.value == nil {
			continue
		}
		if *field.value < 0 {
			return fmt.Errorf("compile cloudflared configuration: originRequest.%s must not be negative", field.name)
		}
		if *field.value%time.Second != 0 {
			return fmt.Errorf("compile cloudflared configuration: originRequest.%s must use whole-second precision", field.name)
		}
	}
	if origin.KeepAliveConnections != nil && *origin.KeepAliveConnections < 0 {
		return errors.New("compile cloudflared configuration: originRequest.keepAliveConnections must not be negative")
	}
	return nil
}

func compileDirectConfig(configuration ir.TunnelConfiguration) (configBody, error) {
	if len(configuration.Ingress) == 0 {
		return configBody{}, errors.New("compile direct cloudflared configuration: ingress is empty")
	}
	if err := validateOriginRequest("originRequest", configuration.OriginRequest); err != nil {
		return configBody{}, err
	}
	if err := validateWARPRouting(configuration.WARPRouting); err != nil {
		return configBody{}, err
	}

	ingress := make([]ingressRule, len(configuration.Ingress))
	for index, rule := range configuration.Ingress {
		location := fmt.Sprintf("ingress[%d]", index)
		isLast := index == len(configuration.Ingress)-1
		catchAll := rule.Hostname == "" && rule.Path == ""
		switch {
		case isLast && !catchAll:
			return configBody{}, fmt.Errorf("compile direct cloudflared configuration: %s must be the catch-all rule with hostname and path omitted", location)
		case !isLast && catchAll:
			return configBody{}, fmt.Errorf("compile direct cloudflared configuration: %s is a catch-all rule before the final rule", location)
		}
		if err := validateHostname(location+".hostname", rule.Hostname); err != nil {
			return configBody{}, err
		}
		if rule.Path != "" {
			if _, err := regexp.Compile(rule.Path); err != nil {
				return configBody{}, fmt.Errorf("compile direct cloudflared configuration: %s.path is not a valid regular expression: %w", location, err)
			}
		}
		service, kind, err := compileService(location+".service", rule.Service)
		if err != nil {
			return configBody{}, err
		}
		if err := validateOriginRequest(location+".originRequest", rule.OriginRequest); err != nil {
			return configBody{}, err
		}
		if rule.OriginRequest != nil && rule.OriginRequest.Access != nil && !isHTTPService(kind) {
			return configBody{}, fmt.Errorf("compile direct cloudflared configuration: %s.originRequest.access is only valid for HTTP origins", location)
		}
		if rule.OriginRequest != nil && len(rule.OriginRequest.IPRules) > 0 && kind != "bastion" &&
			(rule.OriginRequest.ProxyType == nil || *rule.OriginRequest.ProxyType != ir.OriginProxyTypeSOCKS5) {
			return configBody{}, fmt.Errorf("compile direct cloudflared configuration: %s.originRequest.ipRules requires Bastion or SOCKS5 proxy service", location)
		}
		ingress[index] = ingressRule{
			Hostname:      rule.Hostname,
			Path:          rule.Path,
			Service:       service,
			OriginRequest: directOrigin(rule.OriginRequest),
		}
	}
	return configBody{
		Ingress:       ingress,
		OriginRequest: directOrigin(configuration.OriginRequest),
		WARPRouting:   directWARPRouting(configuration.WARPRouting),
	}, nil
}

func validateHostname(location, hostname string) error {
	if hostname == "" {
		return nil
	}
	if strings.TrimSpace(hostname) != hostname || strings.ContainsAny(hostname, "/:@") {
		return fmt.Errorf("compile direct cloudflared configuration: %s %q is invalid", location, hostname)
	}
	if hostname == "*" {
		return nil
	}
	name := strings.TrimPrefix(hostname, "*.")
	if name == "" || strings.Contains(name, "*") {
		return fmt.Errorf("compile direct cloudflared configuration: %s %q is invalid", location, hostname)
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("compile direct cloudflared configuration: %s %q is invalid", location, hostname)
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
				(character < '0' || character > '9') && character != '-' {
				return fmt.Errorf("compile direct cloudflared configuration: %s %q is invalid", location, hostname)
			}
		}
	}
	return nil
}

func compileService(location string, service ir.TunnelIngressService) (string, string, error) {
	type addressChoice struct {
		name    string
		scheme  string
		service *ir.TunnelAddressService
	}
	addresses := []addressChoice{
		{name: "http", scheme: "http", service: service.HTTP},
		{name: "https", scheme: "https", service: service.HTTPS},
		{name: "tcp", scheme: "tcp", service: service.TCP},
		{name: "ssh", scheme: "ssh", service: service.SSH},
		{name: "rdp", scheme: "rdp", service: service.RDP},
		{name: "smb", scheme: "smb", service: service.SMB},
	}
	selected := 0
	wire := ""
	kind := ""
	for _, choice := range addresses {
		if choice.service == nil {
			continue
		}
		selected++
		if err := validateAddress(location+"."+choice.name+".address", choice.service.Address); err != nil {
			return "", "", err
		}
		wire = choice.scheme + "://" + choice.service.Address
		kind = choice.name
	}
	for _, choice := range []struct {
		name    string
		scheme  string
		service *ir.TunnelUnixService
	}{
		{name: "unix", scheme: "unix:", service: service.Unix},
		{name: "unixTLS", scheme: "unix+tls:", service: service.UnixTLS},
	} {
		if choice.service == nil {
			continue
		}
		selected++
		if choice.service.Path == "" || !filepath.IsAbs(choice.service.Path) {
			return "", "", fmt.Errorf("compile direct cloudflared configuration: %s.%s.path %q must be absolute", location, choice.name, choice.service.Path)
		}
		wire = choice.scheme + choice.service.Path
		kind = choice.name
	}
	if service.HelloWorld != nil {
		selected++
		wire, kind = "hello_world", "helloWorld"
	}
	if service.HTTPStatus != nil {
		selected++
		if service.HTTPStatus.Code < 100 || service.HTTPStatus.Code > 599 {
			return "", "", fmt.Errorf("compile direct cloudflared configuration: %s.httpStatus.code %d must be between 100 and 599", location, service.HTTPStatus.Code)
		}
		wire, kind = fmt.Sprintf("http_status:%d", service.HTTPStatus.Code), "httpStatus"
	}
	if service.Bastion != nil {
		selected++
		wire, kind = "bastion", "bastion"
	}
	if selected != 1 {
		return "", "", fmt.Errorf("compile direct cloudflared configuration: %s must select exactly one service, found %d", location, selected)
	}
	return wire, kind, nil
}

func validateAddress(location, address string) error {
	host, portText, err := net.SplitHostPort(address)
	if err != nil || host == "" || portText == "" {
		return fmt.Errorf("compile direct cloudflared configuration: %s %q must be a host:port pair", location, address)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return fmt.Errorf("compile direct cloudflared configuration: %s %q contains an invalid port", location, address)
	}
	return nil
}

func validateOriginRequest(location string, origin *ir.OriginRequest) error {
	if origin == nil {
		return nil
	}
	for _, field := range []struct {
		name  string
		value *int64
	}{
		{name: "connectTimeout", value: origin.ConnectTimeout},
		{name: "tlsTimeout", value: origin.TLSTimeout},
		{name: "tcpKeepAlive", value: origin.TCPKeepAlive},
		{name: "keepAliveConnections", value: origin.KeepAliveConnections},
		{name: "keepAliveTimeout", value: origin.KeepAliveTimeout},
	} {
		if field.value != nil && *field.value < 0 {
			return fmt.Errorf("compile direct cloudflared configuration: %s.%s must not be negative", location, field.name)
		}
	}
	if origin.ProxyType != nil && *origin.ProxyType != ir.OriginProxyTypeRegular && *origin.ProxyType != ir.OriginProxyTypeSOCKS5 {
		return fmt.Errorf("compile direct cloudflared configuration: %s.proxyType %q is invalid", location, *origin.ProxyType)
	}
	for index, rule := range origin.IPRules {
		if _, _, err := net.ParseCIDR(rule.Prefix); err != nil {
			return fmt.Errorf("compile direct cloudflared configuration: %s.ipRules[%d].prefix %q is not a valid CIDR: %w", location, index, rule.Prefix, err)
		}
		for _, port := range rule.Ports {
			if port < 1 || port > 65535 {
				return fmt.Errorf("compile direct cloudflared configuration: %s.ipRules[%d] contains invalid port %d", location, index, port)
			}
		}
	}
	if origin.Access != nil &&
		(origin.Access.TeamName == "" || len(canonicalStrings(origin.Access.AUDTags)) == 0) {
		return fmt.Errorf("compile direct cloudflared configuration: %s.access requires teamName and at least one non-empty audTag", location)
	}
	return nil
}

func validateWARPRouting(routing *ir.WARPRouting) error {
	if routing == nil {
		return nil
	}
	for _, field := range []struct {
		name  string
		value *int64
	}{
		{name: "connectTimeout", value: routing.ConnectTimeout},
		{name: "tcpKeepAlive", value: routing.TCPKeepAlive},
		{name: "maxActiveFlows", value: routing.MaxActiveFlows},
	} {
		if field.value != nil && *field.value < 0 {
			return fmt.Errorf("compile direct cloudflared configuration: warp-routing.%s must not be negative", field.name)
		}
	}
	return nil
}

func isHTTPService(kind string) bool {
	switch kind {
	case "http", "https", "unix", "unixTLS":
		return true
	default:
		return false
	}
}
