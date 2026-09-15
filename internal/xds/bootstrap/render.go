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

// Package bootstrap renders the static Envoy bootstrap and file-backed SDS
// resources used to establish the Delta ADS mTLS connection.
package bootstrap

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

// Bootstrap defaults used when rendering Envoy configuration.
const (
	DefaultXDSAddress = "flareway-xds.flareway-system.svc.cluster.local:18000"
)

// Options identifies an Envoy node and its xDS endpoint.
type Options struct {
	NodeCluster     string
	XDSAddress      string
	ConformanceMode bool
}

// Files contains the three ConfigMap entries mounted under /etc/envoy.
type Files struct {
	BootstrapYAML    string
	ClientSecretYAML string
	CASecretYAML     string
}

// Render returns a Delta ADS bootstrap plus file-SDS resources. NodeCluster is
// the exact "namespace/gateway" value authorized by the xDS server.
func Render(opts Options) (Files, error) {
	if strings.TrimSpace(opts.NodeCluster) == "" || !strings.Contains(opts.NodeCluster, "/") {
		return Files{}, errors.New("node cluster must be namespace/gateway")
	}
	address := strings.TrimSpace(opts.XDSAddress)
	if address == "" {
		address = DefaultXDSAddress
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || port == "" {
		return Files{}, fmt.Errorf("xDS address %q must be host:port", address)
	}

	bootstrap := fmt.Sprintf(`node:
  id: "$(POD_NAMESPACE)/$(GATEWAY_NAME)/$(POD_UID)"
  cluster: %q
admin:
  address:
    socket_address:
      address: 127.0.0.1
      port_value: 19000
static_resources:
  listeners:
  - name: flareway-health
    address:
      socket_address:
        address: 0.0.0.0
        port_value: 19001
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: flareway_health
          route_config:
            name: flareway-health
            virtual_hosts:
            - name: flareway-health
              domains: ["*"]
              routes:
              - match: {prefix: "/"}
                direct_response: {status: 404}
          http_filters:
          - name: envoy.filters.http.health_check
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.health_check.v3.HealthCheck
              pass_through_mode: false
              headers:
              - name: ":path"
                string_match: {exact: "/healthz"}
          - name: envoy.filters.http.router
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
  clusters:
  - name: flareway-xds
    type: STRICT_DNS
    connect_timeout: 5s
    load_assignment:
      cluster_name: flareway-xds
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: %s
                port_value: %s
    typed_extension_protocol_options:
      envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
        "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
        explicit_http_config:
          http2_protocol_options: {}
    transport_socket:
      name: envoy.transport_sockets.tls
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
        sni: %s
        auto_sni_san_validation: true
        common_tls_context:
          tls_params:
            tls_minimum_protocol_version: TLSv1_3
            tls_maximum_protocol_version: TLSv1_3
          tls_certificate_sds_secret_configs:
          - name: xds-client
            sds_config:
              path_config_source:
                path: /etc/flareway/xds/client-secret.yaml
          validation_context_sds_secret_config:
            name: xds-ca
            sds_config:
              path_config_source:
                path: /etc/flareway/xds/ca-secret.yaml
dynamic_resources:
  ads_config:
    api_type: DELTA_GRPC
    transport_api_version: V3
    grpc_services:
    - envoy_grpc:
        cluster_name: flareway-xds
  cds_config: {ads: {}, resource_api_version: V3}
  lds_config: {ads: {}, resource_api_version: V3}
`, opts.NodeCluster, host, port, host)

	return Files{
		BootstrapYAML: bootstrap,
		ClientSecretYAML: `resources:
- "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret
  name: xds-client
  tls_certificate:
    certificate_chain: {filename: /etc/flareway/xds/tls.crt}
    private_key: {filename: /etc/flareway/xds/tls.key}
    watched_directory: {path: /etc/flareway/xds}
`,
		CASecretYAML: `resources:
- "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret
  name: xds-ca
  validation_context:
    trusted_ca: {filename: /etc/flareway/xds/ca.crt}
    watched_directory: {path: /etc/flareway/xds}
`,
	}, nil
}
