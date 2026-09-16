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
	"strings"
	"time"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpointv3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	upstreamhttpv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/isac322/flareway/internal/ir"
)

const httpProtocolOptionsKey = "envoy.extensions.upstreams.http.v3.HttpProtocolOptions"

func buildCluster(in ir.Cluster) (*clusterv3.Cluster, *endpointv3.ClusterLoadAssignment, error) {
	if in.Name == "" {
		return nil, nil, fmt.Errorf("cluster name is required")
	}
	protocolOptions, err := upstreamProtocolOptions(in.AppProtocol)
	if err != nil {
		return nil, nil, err
	}
	out := &clusterv3.Cluster{
		Name:                 in.Name,
		ClusterDiscoveryType: &clusterv3.Cluster_Type{Type: clusterv3.Cluster_EDS},
		ConnectTimeout:       durationpb.New(5 * time.Second),
		EdsClusterConfig: &clusterv3.Cluster_EdsClusterConfig{
			EdsConfig:   adsConfigSource(),
			ServiceName: in.Name,
		},
		LbPolicy: clusterv3.Cluster_ROUND_ROBIN,
		TypedExtensionProtocolOptions: map[string]*anypb.Any{
			httpProtocolOptionsKey: protocolOptions,
		},
	}
	if in.TLS != nil {
		transport, err := buildUpstreamTLS(in.TLS)
		if err != nil {
			return nil, nil, fmt.Errorf("cluster %q BackendTLS: %w", in.Name, err)
		}
		out.TransportSocket = transport
	}

	assignment := &endpointv3.ClusterLoadAssignment{ClusterName: in.Name}
	if len(in.Endpoints) > 0 {
		locality := &endpointv3.LocalityLbEndpoints{}
		for _, endpoint := range in.Endpoints {
			port := endpoint.Port
			if port == 0 {
				port = in.Port
			}
			if endpoint.Address == "" || port <= 0 {
				continue
			}
			locality.LbEndpoints = append(locality.LbEndpoints, &endpointv3.LbEndpoint{
				HostIdentifier: &endpointv3.LbEndpoint_Endpoint{Endpoint: &endpointv3.Endpoint{
					Address: socketAddress(endpoint.Address, uint32(port)),
				}},
			})
		}
		if len(locality.LbEndpoints) > 0 {
			assignment.Endpoints = []*endpointv3.LocalityLbEndpoints{locality}
		}
	}
	return out, assignment, nil
}

func buildSecret(in ir.TLSSecret) (*tlsv3.Secret, error) {
	if in.Name == "" {
		return nil, fmt.Errorf("TLS secret name is required")
	}
	out := &tlsv3.Secret{Name: in.Name}
	switch {
	case len(in.Certificate) > 0 || len(in.PrivateKey) > 0:
		if len(in.Certificate) == 0 || len(in.PrivateKey) == 0 {
			return nil, fmt.Errorf("TLS secret %q must contain both certificate and private key", in.Name)
		}
		out.Type = &tlsv3.Secret_TlsCertificate{TlsCertificate: &tlsv3.TlsCertificate{
			CertificateChain: inlineBytes(in.Certificate),
			PrivateKey:       inlineBytes(in.PrivateKey),
		}}
	case len(in.CA) > 0:
		out.Type = &tlsv3.Secret_ValidationContext{ValidationContext: &tlsv3.CertificateValidationContext{
			TrustedCa: inlineBytes(in.CA),
		}}
	default:
		return nil, fmt.Errorf("TLS secret %q has no material", in.Name)
	}
	return out, nil
}

func buildUpstreamTLS(in *ir.BackendTLS) (*corev3.TransportSocket, error) {
	validation := &tlsv3.CertificateValidationContext{}
	switch {
	case len(in.CACertificate) > 0:
		validation.TrustedCa = inlineBytes(in.CACertificate)
	case in.WellKnownCACertificates != "":
		validation.TrustedCa = filenameDataSource("/etc/ssl/certs/ca-certificates.crt")
	default:
		return nil, fmt.Errorf("a CA certificate source is required")
	}
	for _, san := range in.SubjectAltNames {
		sanType := tlsv3.SubjectAltNameMatcher_DNS
		switch strings.ToLower(san.Type) {
		case "hostname", "dns", "":
			sanType = tlsv3.SubjectAltNameMatcher_DNS
		case "uri":
			sanType = tlsv3.SubjectAltNameMatcher_URI
		default:
			return nil, fmt.Errorf("unsupported subjectAltName type %q", san.Type)
		}
		validation.MatchTypedSubjectAltNames = append(validation.MatchTypedSubjectAltNames, &tlsv3.SubjectAltNameMatcher{
			SanType: sanType,
			Matcher: exactStringMatcher(san.Value),
		})
	}
	context := &tlsv3.UpstreamTlsContext{
		Sni: in.ServerName,
		CommonTlsContext: &tlsv3.CommonTlsContext{
			ValidationContextType: &tlsv3.CommonTlsContext_ValidationContext{ValidationContext: validation},
		},
	}
	typed, err := anypb.New(context)
	if err != nil {
		return nil, fmt.Errorf("marshal upstream TLS context: %w", err)
	}
	return &corev3.TransportSocket{
		Name:       "envoy.transport_sockets.tls",
		ConfigType: &corev3.TransportSocket_TypedConfig{TypedConfig: typed},
	}, nil
}

func buildJWKCluster(host, name string) (*clusterv3.Cluster, error) {
	protocolOptions, err := upstreamProtocolOptions("")
	if err != nil {
		return nil, err
	}
	validation := &tlsv3.CertificateValidationContext{
		TrustedCa: filenameDataSource("/etc/ssl/certs/ca-certificates.crt"),
		MatchTypedSubjectAltNames: []*tlsv3.SubjectAltNameMatcher{{
			SanType: tlsv3.SubjectAltNameMatcher_DNS,
			Matcher: exactStringMatcher(host),
		}},
	}
	tlsContext, err := anypb.New(&tlsv3.UpstreamTlsContext{
		Sni: host,
		CommonTlsContext: &tlsv3.CommonTlsContext{
			ValidationContextType: &tlsv3.CommonTlsContext_ValidationContext{ValidationContext: validation},
		},
	})
	if err != nil {
		return nil, err
	}
	return &clusterv3.Cluster{
		Name:                 name,
		ClusterDiscoveryType: &clusterv3.Cluster_Type{Type: clusterv3.Cluster_STRICT_DNS},
		ConnectTimeout:       durationpb.New(10 * time.Second),
		DnsLookupFamily:      clusterv3.Cluster_V4_ONLY,
		LbPolicy:             clusterv3.Cluster_ROUND_ROBIN,
		LoadAssignment: &endpointv3.ClusterLoadAssignment{
			ClusterName: name,
			Endpoints: []*endpointv3.LocalityLbEndpoints{{
				LbEndpoints: []*endpointv3.LbEndpoint{{
					HostIdentifier: &endpointv3.LbEndpoint_Endpoint{Endpoint: &endpointv3.Endpoint{
						Hostname: host,
						Address:  socketAddress(host, 443),
					}},
				}},
			}},
		},
		TypedExtensionProtocolOptions: map[string]*anypb.Any{httpProtocolOptionsKey: protocolOptions},
		TransportSocket: &corev3.TransportSocket{
			Name:       "envoy.transport_sockets.tls",
			ConfigType: &corev3.TransportSocket_TypedConfig{TypedConfig: tlsContext},
		},
	}, nil
}

func upstreamProtocolOptions(appProtocol string) (*anypb.Any, error) {
	explicit := &upstreamhttpv3.HttpProtocolOptions_ExplicitHttpConfig{}
	if appProtocol == "kubernetes.io/h2c" {
		explicit.ProtocolConfig = &upstreamhttpv3.HttpProtocolOptions_ExplicitHttpConfig_Http2ProtocolOptions{
			Http2ProtocolOptions: &corev3.Http2ProtocolOptions{},
		}
	} else {
		explicit.ProtocolConfig = &upstreamhttpv3.HttpProtocolOptions_ExplicitHttpConfig_HttpProtocolOptions{
			HttpProtocolOptions: &corev3.Http1ProtocolOptions{},
		}
	}
	return anypb.New(&upstreamhttpv3.HttpProtocolOptions{
		UpstreamProtocolOptions: &upstreamhttpv3.HttpProtocolOptions_ExplicitHttpConfig_{ExplicitHttpConfig: explicit},
	})
}

func adsConfigSource() *corev3.ConfigSource {
	return &corev3.ConfigSource{
		ResourceApiVersion: corev3.ApiVersion_V3,
		ConfigSourceSpecifier: &corev3.ConfigSource_Ads{
			Ads: &corev3.AggregatedConfigSource{},
		},
	}
}

func socketAddress(address string, port uint32) *corev3.Address {
	return &corev3.Address{Address: &corev3.Address_SocketAddress{SocketAddress: &corev3.SocketAddress{
		Address:       address,
		PortSpecifier: &corev3.SocketAddress_PortValue{PortValue: port},
	}}}
}

func inlineBytes(data []byte) *corev3.DataSource {
	return &corev3.DataSource{Specifier: &corev3.DataSource_InlineBytes{InlineBytes: append([]byte(nil), data...)}}
}

func filenameDataSource(path string) *corev3.DataSource {
	return &corev3.DataSource{Specifier: &corev3.DataSource_Filename{Filename: path}}
}
