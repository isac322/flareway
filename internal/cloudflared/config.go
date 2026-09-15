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

package cloudflared

import (
	"slices"
	"time"

	"github.com/isac322/flareway/internal/ir"
)

type configBody struct {
	Ingress       []ingressRule  `json:"ingress"`
	OriginRequest *originRequest `json:"originRequest,omitempty"`
	WARPRouting   *warpRouting   `json:"warp-routing,omitempty"`
}

type ingressRule struct {
	Hostname      string         `json:"hostname,omitempty"`
	Path          string         `json:"path,omitempty"`
	Service       string         `json:"service"`
	OriginRequest *originRequest `json:"originRequest,omitempty"`
}

type originRequest struct {
	Access                 *access        `json:"access,omitempty"`
	CAPool                 *string        `json:"caPool,omitempty"`
	ConnectTimeout         *int64         `json:"connectTimeout,omitempty"`
	DisableChunkedEncoding *bool          `json:"disableChunkedEncoding,omitempty"`
	HTTP2Origin            *bool          `json:"http2Origin,omitempty"`
	HTTPHostHeader         *string        `json:"httpHostHeader,omitempty"`
	KeepAliveConnections   *int64         `json:"keepAliveConnections,omitempty"`
	KeepAliveTimeout       *int64         `json:"keepAliveTimeout,omitempty"`
	MatchSNIToHost         *bool          `json:"matchSNItoHost,omitempty"`
	NoHappyEyeballs        *bool          `json:"noHappyEyeballs,omitempty"`
	NoTLSVerify            *bool          `json:"noTLSVerify,omitempty"`
	OriginServerName       *string        `json:"originServerName,omitempty"`
	ProxyType              *string        `json:"proxyType,omitempty"`
	TCPKeepAlive           *int64         `json:"tcpKeepAlive,omitempty"`
	TLSTimeout             *int64         `json:"tlsTimeout,omitempty"`
	IPRules                []originIPRule `json:"ipRules,omitempty"`
}

type originIPRule struct {
	Prefix string  `json:"prefix"`
	Ports  []int32 `json:"ports,omitempty"`
	Allow  bool    `json:"allow"`
}

type access struct {
	AUDTag   []string `json:"audTag"`
	TeamName string   `json:"teamName"`
	Required *bool    `json:"required,omitempty"`
}

type warpRouting struct {
	Enabled        *bool  `json:"enabled,omitempty"`
	ConnectTimeout *int64 `json:"connectTimeout,omitempty"`
	TCPKeepAlive   *int64 `json:"tcpKeepAlive,omitempty"`
	MaxActiveFlows *int64 `json:"maxActiveFlows,omitempty"`
}

type domainRule struct {
	category int
	order    int
	hostname string
	path     string
	service  string
	origin   *originRequest
}

func gatewayOrigin(in ir.GatewayOriginRequest) *originRequest {
	return &originRequest{
		ConnectTimeout:         optionalDurationSeconds(in.ConnectTimeout),
		KeepAliveTimeout:       optionalDurationSeconds(in.KeepAliveTimeout),
		TCPKeepAlive:           optionalDurationSeconds(in.TCPKeepAlive),
		KeepAliveConnections:   clonePointer(in.KeepAliveConnections),
		NoHappyEyeballs:        clonePointer(in.NoHappyEyeballs),
		DisableChunkedEncoding: clonePointer(in.DisableChunkedEncoding),
		HTTP2Origin:            clonePointer(in.HTTP2Origin),
	}
}

func directOrigin(in *ir.OriginRequest) *originRequest {
	if in == nil {
		return nil
	}
	out := &originRequest{
		CAPool:                 clonePointer(in.CAPool),
		ConnectTimeout:         clonePointer(in.ConnectTimeout),
		DisableChunkedEncoding: clonePointer(in.DisableChunkedEncoding),
		HTTP2Origin:            clonePointer(in.HTTP2Origin),
		HTTPHostHeader:         clonePointer(in.HTTPHostHeader),
		KeepAliveConnections:   clonePointer(in.KeepAliveConnections),
		KeepAliveTimeout:       clonePointer(in.KeepAliveTimeout),
		MatchSNIToHost:         clonePointer(in.MatchSNIToHost),
		NoHappyEyeballs:        clonePointer(in.NoHappyEyeballs),
		NoTLSVerify:            clonePointer(in.NoTLSVerify),
		OriginServerName:       clonePointer(in.OriginServerName),
		ProxyType:              wireProxyType(in.ProxyType),
		TCPKeepAlive:           clonePointer(in.TCPKeepAlive),
		TLSTimeout:             clonePointer(in.TLSTimeout),
	}
	if len(in.IPRules) > 0 {
		out.IPRules = make([]originIPRule, len(in.IPRules))
		for index, rule := range in.IPRules {
			out.IPRules[index] = originIPRule{Prefix: rule.Prefix, Ports: canonicalPorts(rule.Ports), Allow: rule.Allow}
		}
	}
	if in.Access != nil {
		out.Access = &access{
			AUDTag:   canonicalStrings(in.Access.AUDTags),
			TeamName: in.Access.TeamName,
			Required: clonePointer(in.Access.Required),
		}
	}
	return out
}

func directWARPRouting(in *ir.WARPRouting) *warpRouting {
	if in == nil {
		return nil
	}
	return &warpRouting{
		Enabled:        clonePointer(in.Enabled),
		ConnectTimeout: clonePointer(in.ConnectTimeout),
		TCPKeepAlive:   clonePointer(in.TCPKeepAlive),
		MaxActiveFlows: clonePointer(in.MaxActiveFlows),
	}
}

func cloneOrigin(in *originRequest) *originRequest {
	if in == nil {
		return nil
	}
	out := *in
	out.Access = nil
	out.CAPool = clonePointer(in.CAPool)
	out.ConnectTimeout = clonePointer(in.ConnectTimeout)
	out.DisableChunkedEncoding = clonePointer(in.DisableChunkedEncoding)
	out.HTTP2Origin = clonePointer(in.HTTP2Origin)
	out.HTTPHostHeader = clonePointer(in.HTTPHostHeader)
	out.KeepAliveConnections = clonePointer(in.KeepAliveConnections)
	out.KeepAliveTimeout = clonePointer(in.KeepAliveTimeout)
	out.MatchSNIToHost = clonePointer(in.MatchSNIToHost)
	out.NoHappyEyeballs = clonePointer(in.NoHappyEyeballs)
	out.NoTLSVerify = clonePointer(in.NoTLSVerify)
	out.OriginServerName = clonePointer(in.OriginServerName)
	out.ProxyType = clonePointer(in.ProxyType)
	out.TCPKeepAlive = clonePointer(in.TCPKeepAlive)
	out.TLSTimeout = clonePointer(in.TLSTimeout)
	if len(in.IPRules) > 0 {
		out.IPRules = make([]originIPRule, len(in.IPRules))
		for index, rule := range in.IPRules {
			out.IPRules[index] = originIPRule{Prefix: rule.Prefix, Ports: canonicalPorts(rule.Ports), Allow: rule.Allow}
		}
	}
	if in.Access != nil {
		copied := *in.Access
		copied.AUDTag = slices.Clone(in.Access.AUDTag)
		copied.Required = clonePointer(in.Access.Required)
		out.Access = &copied
	}
	return &out
}

func optionalDurationSeconds(value *time.Duration) *int64 {
	if value == nil {
		return nil
	}
	seconds := durationSeconds(*value)
	return &seconds
}

func durationSeconds(value time.Duration) int64 {
	return int64(value / time.Second)
}

func clonePointer[T any](value *T) *T {
	if value == nil {
		return nil
	}
	copied := *value
	return &copied
}

func canonicalStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" {
			out = append(out, value)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func canonicalPorts(values []int32) []int32 {
	if len(values) == 0 {
		return nil
	}
	out := slices.Clone(values)
	slices.Sort(out)
	return slices.Compact(out)
}

func wireProxyType(value *ir.OriginProxyType) *string {
	if value == nil || *value == ir.OriginProxyTypeRegular {
		return nil
	}
	wire := "socks"
	return &wire
}
