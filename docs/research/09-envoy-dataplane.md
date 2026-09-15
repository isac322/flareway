# Flareway Research Report: Envoy Data Plane Reference

*As of: 2026-09-13*

---

## Purpose and validation status

This report fixes the Envoy v3 structures that Flareway must generate from Gateway API resources. It contains the M0 reference configuration, the Gateway API-to-Envoy mapping, and the route-ordering contract used by later translator work.

The configuration below is the validation target for Envoy `v1.39.1`. Its M0 container validation is **pending measurement** and will be recorded in `docs/research/10-local-measurements.md`. In particular, the plan intentionally preserves `admin.allow_paths` until that validation determines whether Envoy `v1.39.1` accepts it. This report does not claim an unexecuted validation result.

## Source and pin notes

- Primary specification: approved Flareway implementation plan, Appendix A-1 and Appendix A-2.
- Gateway API model: `sigs.k8s.io/gateway-api v1.6.2`.
- Runtime validation image: `envoyproxy/envoy:v1.39.1`.
- Production runtime image: `envoyproxy/envoy:distroless-v1.39.1`.
- Go protobuf/API pins: `github.com/envoyproxy/go-control-plane v0.14.0` and `github.com/envoyproxy/go-control-plane/envoy v1.39.0`.
- Envoy evaluates routes in list order. Flareway must calculate Gateway API precedence before emitting `VirtualHost.routes`.
- The reference uses static resources only to validate field shapes and filter composition. The operator implementation will deliver listeners, routes, clusters, endpoints, and secrets through Delta ADS and SDS.

---

## Reference Envoy configuration

The canonical repository copy is `hack/envoy-reference.yaml`.

```yaml
node: {id: flareway-reference, cluster: flareway-reference}
admin:
  address:
    socket_address: {address: 127.0.0.1, port_value: 19000}
  allow_paths:
  - {exact: /ready}
  - {exact: /server_info}
  - {exact: /drain_listeners}
static_resources:
  secrets:
  - name: private-listener-cert
    tls_certificate:
      certificate_chain: {filename: /etc/envoy/tls/tls.crt}
      private_key: {filename: /etc/envoy/tls/tls.key}
  listeners:
  - name: public-http
    address: {socket_address: {address: 127.0.0.1, port_value: 18080}}
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: public
          normalize_path: true
          merge_slashes: true
          path_with_escaped_slashes_action: UNESCAPE_AND_REDIRECT
          stream_idle_timeout: 0s
          common_http_protocol_options: {idle_timeout: 0s}
          upgrade_configs: [{upgrade_type: websocket}]
          route_config:
            name: public-routes
            virtual_hosts:
            - name: example
              domains: ["example.com", "*.example.com"]
              routes:
              - name: exact-method-header-query
                match:
                  path: /v1/items
                  headers:
                  - name: :method
                    string_match: {exact: GET}
                  - name: x-tenant
                    string_match: {exact: blue}
                  query_parameters:
                  - name: verbose
                    string_match: {exact: "true"}
                route:
                  weighted_clusters:
                    clusters:
                    - {name: backend-a, weight: 80}
                    - {name: backend-b, weight: 20}
                  timeout: 15s
                  idle_timeout: 0s
                  request_mirror_policies:
                  - cluster: mirror
                    runtime_fraction: {default_value: {numerator: 100, denominator: HUNDRED}}
                request_headers_to_add:
                - header: {key: x-flareway-route, value: items}
                  append_action: OVERWRITE_IF_EXISTS_OR_ADD
                request_headers_to_remove: [x-remove-me]
                response_headers_to_add:
                - header: {key: x-content-type-options, value: nosniff}
                  append_action: OVERWRITE_IF_EXISTS_OR_ADD
                response_headers_to_remove: [server]
                typed_per_filter_config:
                  envoy.filters.http.cors:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.cors.v3.CorsPolicy
                    allow_origin_string_match: [{exact: "https://app.example.com"}]
                    allow_methods: "GET,OPTIONS"
                    allow_headers: "content-type,x-tenant"
                    expose_headers: "x-request-id"
                    max_age: "600"
                    allow_credentials: true
              - name: redirect
                match: {path_separated_prefix: /old}
                redirect:
                  scheme_redirect: https
                  host_redirect: example.com
                  prefix_rewrite: /new
                  response_code: PERMANENT_REDIRECT
              - name: regex-rewrite
                match: {safe_regex: {regex: "^/users/([0-9]+)$"}}
                route:
                  cluster: backend-a
                  timeout: 0s
                  idle_timeout: 0s
                  regex_rewrite:
                    pattern: {regex: "^/users/([0-9]+)$"}
                    substitution: "/profiles/\\1"
              - name: prefix-rewrite
                match: {path_separated_prefix: /api}
                route: {cluster: backend-a, prefix_rewrite: /, timeout: 30s}
          http_filters:
          - name: envoy.filters.http.cors
            typed_config: {"@type": type.googleapis.com/envoy.extensions.filters.http.cors.v3.Cors}
          - name: envoy.filters.http.router
            typed_config: {"@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router}
  - name: access-jwt-http
    address: {socket_address: {address: 127.0.0.1, port_value: 18081}}
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: access
          normalize_path: true
          merge_slashes: true
          path_with_escaped_slashes_action: UNESCAPE_AND_REDIRECT
          stream_idle_timeout: 0s
          upgrade_configs: [{upgrade_type: websocket}]
          route_config:
            name: access-routes
            virtual_hosts:
            - name: protected
              domains: [protected.example.com]
              routes:
              - match: {prefix: /}
                route: {cluster: backend-a, timeout: 30s, idle_timeout: 0s}
          http_filters:
          - name: envoy.filters.http.jwt_authn
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.jwt_authn.v3.JwtAuthentication
              providers:
                cloudflare-access:
                  issuer: https://TEAM.cloudflareaccess.com
                  audiences: ["<aud>"]
                  remote_jwks:
                    http_uri:
                      uri: https://TEAM.cloudflareaccess.com/cdn-cgi/access/certs
                      cluster: cloudflare-jwks
                      timeout: 5s
                    cache_duration: 300s
                  from_headers: [{name: Cf-Access-Jwt-Assertion}]
                  from_cookies: [CF_Authorization]
                  forward: true
              rules:
              - match: {prefix: /}
                requires: {provider_name: cloudflare-access}
          - name: envoy.filters.http.router
            typed_config: {"@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router}
  - name: private-tls
    address: {socket_address: {address: 127.0.0.1, port_value: 18443}}
    filter_chains:
    - transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
          common_tls_context:
            tls_certificate_sds_secret_configs:
            - {name: private-listener-cert}
      filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: private
          normalize_path: true
          merge_slashes: true
          path_with_escaped_slashes_action: UNESCAPE_AND_REDIRECT
          stream_idle_timeout: 0s
          upgrade_configs: [{upgrade_type: websocket}]
          route_config:
            name: private-routes
            virtual_hosts:
            - name: private
              domains: [private.example.internal]
              routes:
              - match: {prefix: /}
                route: {cluster: backend-a, timeout: 0s, idle_timeout: 0s}
          http_filters:
          - name: envoy.filters.http.jwt_authn
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.jwt_authn.v3.JwtAuthentication
              providers:
                cloudflare-access:
                  issuer: https://TEAM.cloudflareaccess.com
                  audiences: ["<aud>"]
                  remote_jwks:
                    http_uri:
                      uri: https://TEAM.cloudflareaccess.com/cdn-cgi/access/certs
                      cluster: cloudflare-jwks
                      timeout: 5s
                    cache_duration: 300s
                  from_headers: [{name: Cf-Access-Jwt-Assertion}]
                  from_cookies: [CF_Authorization]
                  forward: true
              rules:
              - match: {prefix: /}
                requires: {provider_name: cloudflare-access}
          - name: envoy.filters.http.router
            typed_config: {"@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router}
  clusters:
  - name: backend-a
    connect_timeout: 5s
    type: STRICT_DNS
    load_assignment:
      cluster_name: backend-a
      endpoints:
      - lb_endpoints:
        - endpoint:
            address: {socket_address: {address: backend-a.default.svc.cluster.local, port_value: 8080}}
  - name: backend-b
    connect_timeout: 5s
    type: EDS
    eds_cluster_config: {eds_config: {ads: {}}, service_name: backend-b}
  - name: mirror
    connect_timeout: 5s
    type: STRICT_DNS
    load_assignment:
      cluster_name: mirror
      endpoints:
      - lb_endpoints:
        - endpoint:
            address: {socket_address: {address: mirror.default.svc.cluster.local, port_value: 8080}}
  - name: cloudflare-jwks
    connect_timeout: 5s
    type: STRICT_DNS
    load_assignment:
      cluster_name: cloudflare-jwks
      endpoints:
      - lb_endpoints:
        - endpoint:
            address: {socket_address: {address: TEAM.cloudflareaccess.com, port_value: 443}}
    transport_socket:
      name: envoy.transport_sockets.tls
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
        sni: TEAM.cloudflareaccess.com
        auto_sni_san_validation: true
        common_tls_context:
          validation_context:
            trusted_ca: {filename: /etc/ssl/certs/ca-certificates.crt}
```

---

## Gateway API to Envoy v3 mapping

| Gateway API v1.6.2 / design §4.4 feature | Exact Envoy v3 construct |
|---|---|
| Listener bind, port, protocol | `envoy.config.listener.v3.Listener.address.socket_address`; HCM in `Listener.filter_chains[].filters[].typed_config` |
| Hostname intersection and exact host | `RouteConfiguration.virtual_hosts[].domains[]`; exact domain string |
| Wildcard hostname | `VirtualHost.domains: ["*.example.com"]`; Envoy suffix wildcards match deeper names but not the apex, matching Gateway API semantics |
| Exact path | `Route.match.path` |
| PathPrefix | `Route.match.path_separated_prefix`; use `prefix: "/"` only for root |
| RegularExpression path | `Route.match.safe_regex.regex` using RE2 whole-path matching |
| Method match | `Route.match.headers[]` with `name: ":method"` and `string_match.exact` |
| Header exact/regex | `Route.match.headers[].string_match.{exact|safe_regex}` |
| Query parameter exact/regex | `Route.match.query_parameters[].string_match.{exact|safe_regex}` |
| BackendRef single | `Route.route.cluster` |
| `backendRefs.weight` | `Route.route.weighted_clusters.clusters[].{name,weight}` and optional `total_weight` |
| Invalid backend proportional 500 | Include a weighted target representing direct failure, or split the match into runtime-fraction routes; never silently renormalize valid weights. The translator design fixes the exact mechanism. |
| `RequestHeaderModifier` | `Route.request_headers_to_add[]` with `append_action`, and `Route.request_headers_to_remove[]` |
| `ResponseHeaderModifier` | `Route.response_headers_to_add[]` with `append_action`, and `Route.response_headers_to_remove[]` |
| Host rewrite | `RouteAction.host_rewrite_literal`; per-backend variant `WeightedCluster.ClusterWeight.host_rewrite_literal` |
| ReplaceFullPath | Envoy 1.39 `RouteAction.path_rewrite`; the older compatible pattern is anchored `regex_rewrite` |
| ReplacePrefixMatch | `RouteAction.prefix_rewrite` paired with `path_separated_prefix` |
| `RequestRedirect` scheme/host/port/path/status | `Route.redirect.{scheme_redirect,host_redirect,port_redirect,path_redirect|prefix_rewrite|regex_rewrite,response_code}`; codes map to `MOVED_PERMANENTLY` (301), `FOUND` (302), `SEE_OTHER` (303), `TEMPORARY_REDIRECT` (307), and `PERMANENT_REDIRECT` (308) |
| Request mirror | `RouteAction.request_mirror_policies[].cluster` |
| Multiple/percentage mirrors | Repeated `request_mirror_policies[]`; `runtime_fraction.default_value.{numerator,denominator}` |
| CORS | Install `envoy.filters.http.cors`; attach `envoy.extensions.filters.http.cors.v3.CorsPolicy` under `Route.typed_per_filter_config["envoy.filters.http.cors"]` |
| Request timeout | `RouteAction.timeout` |
| Backend timeout with retries off | `RouteAction.timeout` is the only upstream request bound without attempts. Do not set `retry_policy`; `per_try_timeout` exists only inside retry policy. A translator test must cover the case where both Gateway `request` and `backendRequest` are set. |
| Streaming | `RouteAction.timeout: 0s`, `RouteAction.idle_timeout: 0s`, and HCM `stream_idle_timeout: 0s` or the configured global stream timeout |
| WebSocket | `HttpConnectionManager.upgrade_configs[].upgrade_type: websocket` or route-level `RouteAction.upgrade_configs[]` |
| BackendTLSPolicy + SAN | Cluster `transport_socket` with `UpstreamTlsContext.common_tls_context.validation_context.{trusted_ca,match_typed_subject_alt_names[]}` plus `sni` or `auto_sni_san_validation` |
| Service DNS | DNS cluster (`cluster_type: envoy.clusters.dns` preferred; legacy `type: STRICT_DNS` accepted) plus `load_assignment` hostname |
| EndpointSlice endpoints | `Cluster.type: EDS`, `Cluster.eds_cluster_config`, and `ClusterLoadAssignment.endpoints[].lb_endpoints[]` through EDS |
| Listener isolation | Separate Listener/HCM/RDS names per protection domain; no catch-all virtual host may carry another listener's routes |
| Misdirected HTTPS | SNI filter-chain and virtual-host isolation; unmatched SNI or authority must not fall through to another listener's host |

---

## Route-ordering contract

Envoy uses first-match routing. The translator must flatten each accepted `HTTPRouteRule.matches[]` entry into a separate Envoy route and sort routes globally within each listener, protection domain, and virtual host.

1. Select the host first. Keep exact hostnames separate from wildcard hostnames. Among matching hostnames, exact and longer matches win according to Gateway API hostname precedence.
2. Sort `Exact` paths before every other path type.
3. Sort `RegularExpression` paths after `Exact` and before `PathPrefix`. Gateway API leaves regex precedence implementation-specific; Flareway fixes it here.
4. Sort `PathPrefix` paths by descending character length. This keeps `/v1` semantics distinct from `/v10`; the translator uses `path_separated_prefix` rather than a raw string prefix.
5. Sort matches with an HTTP method before matches without one.
6. Sort by descending header matcher count.
7. Sort by descending query parameter matcher count.
8. Sort older `HTTPRoute.metadata.creationTimestamp` values first.
9. Sort by lexical `namespace/name`.
10. Sort by original rule index, then original match index.

The compiler must not rely on Envoy to infer Gateway API precedence. Envoy only evaluates the emitted route list from top to bottom.
