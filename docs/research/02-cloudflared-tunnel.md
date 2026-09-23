# Flareway Research Report: Cloudflare Tunnel & cloudflared Integration

*As of: 2026-09-12*

---

## Summary (10 bullets max)

1. **Config API Single-Writer Model**: The remote tunnel configuration API (`PUT /accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations`) is an atomic whole-object replacement; no rule-level patch endpoint exists, meaning concurrent route controllers will overwrite each other without an orchestrator-level merge.
2. **Push-Based Config Distribution**: `cloudflared` does not poll for configuration; Cloudflare edge pushes updates over the established QUIC/HTTP2 control stream (`tunnelrpc` method `UpdateConfig(version, config)`), applying new ingress configurations sub-second via atomic copy-on-write proxy swaps.
3. **Ingress Rule Ordering & Catch-All**: Rules evaluate sequentially (first match wins); hostnames match exact or single-level wildcards (`*.example.com`); paths evaluate as unanchored Go regular expressions (`regexp.MatchString`), and the final rule must be a catch-all (typically `service: http_status:404`).
4. **L7 Expressiveness Deficit**: `cloudflared` ingress possesses zero capability for HTTP header, method, or query parameter matching, traffic splitting (weights), URL redirects, URL rewrites (paths to origin are strictly identical to eyeball requests), header mutation, or request mirroring.
5. **GatewayHTTP Conformance Requires Envoy**: Because Gateway API `HTTPRoute` requires header/method/query matching, URL rewriting/redirecting, and weighted multi-backend routing, `cloudflared` cannot implement GatewayHTTP alone; an in-pod or sidecar proxy (e.g. Envoy) is mandatory for conformance.
6. **Built-in Access JWT Validation**: `cloudflared` includes native middleware for `originRequest.access` that parses `Cf-Access-Jwt-Assertion`, validates signatures against `https://<teamName>.cloudflareaccess.com/cdn-cgi/access/certs` (cached via OIDC JWKS remote key set), and enforces AUD tags, but this runs strictly on L7 HTTP/HTTPS/WS ingress.
7. **Tunnel Lifecycle & Token Bootstrapping**: Tunnels are provisioned via `POST /accounts/{account_id}/cfd_tunnel` (`config_src: "cloudflare"`), credentials retrieved via `GET .../token` (base64-encoded token containing AccountTag, TunnelID, and TunnelSecret), and connectors run stateless replicas via `cloudflared tunnel run --token <TOKEN>`.
8. **DNS & Certificate Boundaries**: Public hostnames map to tunnels via DNS CNAME records pointing to `<tunnel-id>.cfargotunnel.com` (`proxied: true`). Universal SSL covers apex and first-level subdomains (`*.domain.com`); multi-level subdomains (`*.api.domain.com`) require Advanced Certificate Manager (ACM).
9. **Private Networking Dual Tracks**: Private routing supports CIDR subnet routes via `/accounts/{id}/teamnet/routes` attached to Virtual Networks, as well as GA Private Hostname Routes (`POST /accounts/{id}/zerotrust/routes/hostname`) that steer private domains directly into tunnels without CIDR mapping.
10. **Kubernetes Integration Surface**: `cloudflared` can route directly to Kubernetes ClusterIP service DNS names (via cluster CoreDNS `/etc/resolv.conf`) or to `localhost:<port>` / UNIX domain sockets within the same Pod, exposing Prometheus metrics (`/metrics`), Kubernetes readiness probes (`/ready`), and liveness probes (`/healthcheck`).

---

## Config API and single-writer semantics

### Endpoints and HTTP Methods
Remotely-managed tunnel configurations are governed by Cloudflare API v4 endpoints:
- **Update Configuration**: `PUT /accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations`
- **Get Configuration**: `GET /accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations`

### Request & Response Schema
The update request body adheres to the following structure:
```json
{
  "config": {
    "ingress": [
      {
        "hostname": "app.example.com",
        "path": "^/api/v1/.*",
        "service": "http://my-svc.default.svc.cluster.local:8080",
        "originRequest": {
          "connectTimeout": 30,
          "noTLSVerify": false
        }
      },
      {
        "service": "http_status:404"
      }
    ],
    "originRequest": {
      "connectTimeout": 30,
      "tcpKeepAlive": 30,
      "keepAliveTimeout": 90
    },
    "warp-routing": {
      "enabled": true
    }
  }
}
```

Response payload:
```json
{
  "success": true,
  "errors": [],
  "messages": [],
  "result": {
    "account_id": "<account_id>",
    "tunnel_id": "<tunnel_uuid>",
    "version": 14,
    "source": "cloudflare",
    "created_at": "2026-02-18T22:41:43.534395Z",
    "config": {
      "ingress": [...],
      "originRequest": {...},
      "warp-routing": {"enabled": true}
    }
  }
}
```

### Single-Writer Semantics & Versioning
- **Wholesale Replacement**: The API does not provide a sub-resource or patch endpoint for individual ingress rules (e.g. no `POST .../ingress` or `PATCH .../ingress/3`). Every `PUT` replaces the entire `ingress` array and configuration wholesale.
- **Config Versioning**: The response returns an incrementing integer `version: <int64>`. However, the `PUT` endpoint accepts no conditional concurrency headers (`If-Match`) or request-body version tags. The latest `PUT` unconditionally overwrites Cloudflare's database and pushes that new version.
- **Orchestrator Concurrency Impact**: Because the ingress list is whole-object single-writer, Flareway cannot safely allow independent per-route reconcilers to write to the Cloudflare API directly. Flareway must implement an internal controller pipeline that aggregates all `HTTPRoute` resources matching a Gateway into an in-memory unified ingress list before committing an atomic `PUT`.

### Update Propagation & Latency
1. When the API accepts a `PUT`, the configuration is persisted and edge nodes receive an invalidation.
2. Connected `cloudflared` instances maintain an active multiplexed control stream over QUIC/HTTP2 to edge servers.
3. Edge uses RPC protocol `tunnelrpc` to call `UpdateConfig(version int32, config []byte)` directly on the connected `cloudflared` connectors.
4. In `cloudflared` (`orchestration/orchestrator.go`), `UpdateConfig`:
   - Checks `if o.currentVersion >= version`: drops stale or out-of-order deliveries.
   - Deserializes the JSON and validates ingress rules.
   - Instantiates a new `proxy.Proxy` origin router and atomically swaps the reference via `atomic.Value` (copy-on-write).
   - Signals background graceful shutdown of the old proxy.
   - Increments the Prometheus metric `cloudflared_orchestration_config_version`.
5. **Propagation Latency**: Sub-second to ~2 seconds from API acknowledgment to local runtime activation across all active replicas.

### Limits
| Resource / Entity | Documented Limit | Source |
| :--- | :--- | :--- |
| **cloudflared tunnels per account** | 1,000 | Account limits (Sep 2026) |
| **Active cloudflared replicas per tunnel** | 25 | Account limits (Sep 2026) |
| **Routes (CIDR + Hostname routes) per account** | 1,000 (shared with Cloudflare Mesh) | Account limits (Sep 2026) |
| **Virtual networks per account** | 1,000 | Account limits (Sep 2026) |
| **Ingress rules per tunnel** | ~1,000 recommended (soft payload bound by API request size limits ~1-2 MB) | `[unverified]` hard ceiling; tested to >500 rules |

---

## Ingress matching semantics

### Matching Rules & Execution
- **Host Matching**:
  - Exact: `app.example.com` matches `app.example.com`.
  - Wildcard: Only single leading wildcards are permitted (e.g. `*.example.com`). Wildcards cannot appear anywhere else (`errBadWildcard`).
  - Suffix Check: In `cloudflared/ingress/ingress.go`, `matchHost` tests `strings.HasSuffix(reqHost, toMatch)` where `toMatch = strings.TrimPrefix(ruleHost, "*")`. Thus `*.example.com` matches `sub.example.com` and `a.b.example.com`, but does *not* match apex `example.com`.
  - Host header ports are stripped via `net.SplitHostPort` before comparison.
- **Path Matching**:
  - Path strings are compiled using standard Go regex: `regexp.Compile(r.Path)`.
  - Matching executes via `r.Path.Regexp.MatchString(path)`.
  - **Unanchored**: The regex is unanchored by default. A rule `path: /admin` matches `/admin`, `/v1/admin`, and `/administrator`. Explicit anchors (`^/admin(/.*)?$`) must be generated if strict prefix or exact behavior is needed.
- **Rule Order**:
  - First match wins. `cloudflared` iterates over `ingress` from index `0` to `len-1`.
- **Catch-All Requirement**:
  - The final rule in the list MUST NOT have a `hostname` or `path` filter.
  - If the last rule specifies a hostname/path, or if any rule before the last rule omits both hostname and path, `cloudflared` rejects the configuration with `errLastRuleNotCatchAll` or `ruleShouldNotBeCatchAllError`.
  - Standard catch-all destination: `service: http_status:404` or `service: http_status:503`.
- **Supported `service` Schemes**:
  - `http://<host>:<port>`
  - `https://<host>:<port>`
  - `tcp://<host>:<port>`
  - `ssh://<host>:<port>`
  - `rdp://<host>:<port>`
  - `smb://<host>:<port>`
  - `unix:<socket-path>` (HTTP over UNIX domain socket)
  - `unix+tls:<socket-path>` (HTTPS over UNIX domain socket)
  - `hello_world` (embedded test HTTP server)
  - `http_status:<code>` (embedded responder returning numeric HTTP status code, e.g. `http_status:404`)
  - `bastion` (starts jump-host proxy)
- **Path Rewriting Forbidden**:
  - `cloudflared` strictly enforces that `service` URLs cannot contain a path (`ingress/ingress.go:316`):
    `"ingress rules don't support proxying to a different path on the origin service. The path will be the same as the eyeball request's path"`.
- **Kubernetes Networking Capability**:
  - `cloudflared` uses standard Go `net.Dialer`. It can route to internal Kubernetes ClusterIP DNS records (e.g. `http://service.namespace.svc.cluster.local:8080`), Pod IPs, or `http://127.0.0.1:<port>` when co-located in the same Pod.

### Capability Matrix: Gateway API HTTPRoute vs cloudflared Ingress

| Gateway API HTTPRoute Capability | HTTPRoute Conformance Tier | cloudflared Native Ingress Support | Notes & Gaps in cloudflared |
| :--- | :--- | :--- | :--- |
| **Exact Path Match** (`/foo`) | Core | Partial | Requires synthetic regex generation: `^/foo$` |
| **Prefix Path Match** (`/foo`) | Core | Partial | Requires synthetic regex generation: `^/foo(/.*)?$` |
| **Regex Path Match** | Extended / ImplementationSpecific | Full | Go `regexp.Compile`, unanchored by default |
| **Header Match** (Exact, Regex) | Core | **None** | `cloudflared` cannot evaluate request headers for routing |
| **HTTP Method Match** (GET, POST...) | Core | **None** | `cloudflared` cannot evaluate HTTP methods for routing |
| **Query Param Match** | Core | **None** | `cloudflared` does not inspect query parameters |
| **Weighted Routing (Traffic Splitting)**| Core | **None** | Each ingress rule maps 1:1 to a single service target |
| **URL Redirect Filter** (`RequestRedirect`)| Core | **None** | `http_status:301` returns bare status with no `Location` header |
| **URL Rewrite Filter** (`URLRewrite`)| Extended | **None (Explicitly Forbidden)** | Fails validation if origin URL includes any path prefix |
| **Header Mutation** (Add, Set, Remove) | Core | Partial (Host header only)| Only `originRequest.httpHostHeader` supported; no custom headers |
| **Request Mirroring** (`RequestMirror`)| Extended | **None** | No request duplication or shadowing capability |
| **Timeouts** (`request`, `backendRequest`)| Extended | Partial | Only TCP `connectTimeout` and `tlsTimeout`; no overall request timeout |
| **Retries** (GEP-1742) | Extended | **None** | Configurable only at edge transport layer, not per route |
| **Cross-Namespace Backends** (`ReferenceGrant`) | Core | Out-of-band | Can dial any cluster FQDN; lacks Kubernetes RBAC awareness |

**Conclusion**: Native `cloudflared` ingress cannot satisfy Gateway API GatewayHTTP conformance without an intermediary L7 data-plane proxy (such as Envoy) handling HTTPRoute match rules, traffic splitting, filters, and header mutations.

---

## originRequest parameters

Origin parameters configure how `cloudflared` dials and communicates with backend services. They can be defined globally under `config.originRequest` or overridden on individual ingress rules under `config.ingress[].originRequest`.

| Field Name | Type | Default | Scope | Description |
| :--- | :--- | :--- | :--- | :--- |
| `connectTimeout` | `duration` (string / int64 s) | `30s` | Global & Rule | Timeout for establishing new TCP connection to origin (excluding TLS handshake). |
| `tlsTimeout` | `duration` (string / int64 s) | `10s` | Global & Rule | Timeout for completing TLS handshake to an HTTPS origin. |
| `tcpKeepAlive` | `duration` (string / int64 s) | `30s` | Global & Rule | Interval for TCP keepalive probe packets to origin. |
| `noHappyEyeballs` | `bool` | `false` | Global & Rule | Disables IPv4/IPv6 Happy Eyeballs fallback algorithm. |
| `keepAliveConnections`| `int` | `100` | Global & Rule | Max idle keepalive connections in pool per origin service (does not limit concurrent active streams). |
| `keepAliveTimeout` | `duration` (string / int64 s) | `90s` (`1m30s`) | Global & Rule | Idle connection pool eviction timeout. |
| `httpHostHeader` | `string` | `""` | Global & Rule | Overrides `Host` header sent to local origin webserver. |
| `originServerName` | `string` | `""` | Global & Rule | Expected SNI / hostname on origin TLS certificate. |
| `matchSNItoHost` | `bool` | `false` | Global & Rule | Automatically sets TLS SNI to match the request's HTTP Host header. |
| `caPool` | `string` | `""` | Global & Rule | Local filesystem path to custom CA certificate bundle (`.pem`/`.crt`) for origin verification. |
| `noTLSVerify` | `bool` | `false` | Global & Rule | Disables origin TLS certificate verification. Accepts self-signed/untrusted certificates. |
| `disableChunkedEncoding`| `bool` | `false` | Global & Rule | Disables chunked transfer encoding (for WSGI/legacy servers). |
| `bastionMode` | `bool` | `false` | Global & Rule | Runs origin as SSH bastion jump-host. |
| `proxyAddress` | `string` | `"127.0.0.1"` | Local config only | Listen address for translation proxy (SSH/RDP). |
| `proxyPort` | `uint` | `0` (random) | Local config only | Listen port for translation proxy. |
| `proxyType` | `string` | `""` | Global & Rule | Proxy protocol translation type: `""` (standard) or `"socks"` (SOCKS5). |
| `ipRules` | `[]struct` | `nil` | Rule | Ingress IP CIDR allow/deny firewall rules for proxy services. |
| `http2Origin` | `bool` | `false` | Global & Rule | Forces `cloudflared` to connect to HTTPS origin using HTTP/2 instead of HTTP/1.1. |
| `access` | `AccessConfig` | `nil` | Global & Rule | Configures Zero Trust Access JWT validation middleware on incoming requests. |

---

## Access JWT validation in cloudflared

### Verification Workflow & Implementation
When `originRequest.access` is configured on an ingress rule, `cloudflared` activates its `JWTValidator` middleware (`ingress/middleware/jwtvalidator.go`):

```yaml
originRequest:
  access:
    required: true
    teamName: "my-team"
    audTag:
      - "64e031a07062491a9df7c94b796be23408542031"
```

1. **Header Inspection**:
   - `JWTValidator.Handle` inspects strictly the HTTP request header:
     `Cf-Access-Jwt-Assertion: <jwt>`
   - It does **not** inspect or parse cookies (e.g. `CF_Authorization` cookie is ignored by this middleware; cookie extraction occurs at Cloudflare edge).
2. **Missing Token Handling**:
   - If `Cf-Access-Jwt-Assertion` is empty or missing, the middleware immediately halts request forwarding and returns:
     `StatusCode: 403 Forbidden` (`Reason: "no access token in request"`).
3. **Cryptographic Validation**:
   - Cloudflare Public Key JWKS URL is constructed:
     `https://<teamName>.cloudflareaccess.com/cdn-cgi/access/certs` (or `fed.cloudflareaccess.com` for FedRAMP).
   - Validated via `github.com/coreos/go-oidc/v3/oidc`.
   - The OIDC `RemoteKeySet` automatically caches signing keys in memory and respects HTTP Cache-Control headers, refreshing asynchronously when unseen Key IDs (`kid`) are encountered.
   - Verifies token signature, expiration (`exp`), and Issuer (`iss == https://<teamName>.cloudflareaccess.com`).
4. **Audience Tag Validation**:
   - Iterates through `token.Audience`.
   - Confirms that at least one audience in the JWT matches an entry in `audTag: []string`.
   - If no audience matches, returns `403 Forbidden` (`Reason: "Invalid token in jwt: <aud>"`).
5. **Inheritance & Overrides**:
   - Per-rule `originRequest.access` overrides top-level `originRequest.access` wholesale (`ingress/config.go:setConfig`).
6. **L7 Protocol Restriction**:
   - `JWTValidator` runs strictly inside `ProxyHTTP` (`proxy/proxy.go:applyIngressMiddleware`).
   - It is executed **only** for `http://`, `https://`, `ws://`, and `wss://` ingress targets. Non-HTTP services (raw TCP, SSH, RDP, WARP packet routing) do not pass through HTTP middleware and cannot execute this JWT assertion check.

---

## Tunnel lifecycle & health

### Tunnel Creation & Tokens
1. **Creation**: `POST /accounts/{account_id}/cfd_tunnel`
   ```json
   {
     "name": "flareway-k8s-tunnel",
     "config_src": "cloudflare"
   }
   ```
   - Setting `config_src: "cloudflare"` establishes a remotely-managed tunnel, delegating ingress routing to the configurations API.
   - Cloudflare assigns a UUID (`tunnel_id`) and creates an account-level tunnel credential.
2. **Token Retrieval**: `GET /accounts/{account_id}/cfd_tunnel/{tunnel_id}/token`
   - Returns a base64-encoded JSON blob containing:
     ```json
     {
       "AccountTag": "<account_id>",
       "TunnelID": "<tunnel_uuid>",
       "TunnelSecret": "<base64_secret>"
     }
     ```
   - `cloudflared` can boot with `--token <TOKEN>` without needing local credentials files mounted.

### Deletion & Cleanup
- **Endpoint**: `DELETE /accounts/{account_id}/cfd_tunnel/{tunnel_id}?cascade=true`
- **Dependency Guard**: Cloudflare API rejects tunnel deletion if the tunnel has active connectors, assigned DNS routes, or attached CIDR routes.
- **Cascade Parameter**: Supplying `cascade=true` forces deletion of all associated connections and teamnet routes attached to the tunnel.

### Connector States & Health
The tunnel object reports status aggregated across active connectors:
- `inactive`: Tunnel created, but zero connectors have connected.
- `healthy`: Active connector connections established across multiple colos.
- `degraded`: Some connections have disconnected or are experiencing high latency/packet loss.
- `down`: All connectors previously active are now disconnected.

### Metrics, Readiness & Probes
`cloudflared` runs an internal HTTP server for observability (default address `localhost:20241-20245`, configurable via `--metrics 0.0.0.0:20211` or env `TUNNEL_METRICS`):
- **/ready**: Designed for Kubernetes readiness checks. Returns `200 OK` (`{"status":200,"readyConnections":4,"connectorId":"..."}`) if `tracker.CountActiveConns() > 0`. Returns `503 Service Unavailable` if 0 active edge connections exist.
- **/metrics**: Prometheus metrics scraping endpoint (`promhttp.Handler()`). Key metrics include `cloudflared_tunnel_active_streams`, `cloudflared_tunnel_total_requests`, and `cloudflared_orchestration_config_version`.
- **/healthcheck**: Liveness check returning `200 OK` (`OK\n`).
- **/config**: Returns current versioned runtime configuration JSON.

### Graceful Shutdown & Drain Behavior
- Configured via `--grace-period <duration>` (default `30s`, maximum permitted `connection.MaxGracePeriod = 3m0s`).
- When `SIGINT` or `SIGTERM` is received, `cloudflared`:
  1. Closes the readiness probe (`/ready` begins returning 503).
  2. Sends disconnect notifications to edge colos to stop accepting new eyeball sessions.
  3. Waits for in-flight requests and streams to terminate until the grace period expires.
  4. Immediate termination occurs if a second `SIGINT`/`SIGTERM` is received.

### Replica Count Recommendations
- Production high availability requires at least **2 replicas** per tunnel, ideally scheduled on separate Kubernetes nodes. Flareway implements the node-spread preference as a soft default pod anti-affinity on `kubernetes.io/hostname` in the dataplane Deployment; `GatewayClassConfig.spec.scheduling` controls dataplane placement.
- Each replica creates 4 redundant duplex connections across distinct Cloudflare edge points of presence (PoPs).
- Maximum active replicas per tunnel: **25** (Account limits table).

### Edge Protocol Options
Configured via `--protocol <proto>` (or env `TUNNEL_TRANSPORT_PROTOCOL`):
- `auto` (Default & recommended): Initiates connection via QUIC (UDP port 7844). If UDP egress is blocked by network firewalls, automatically falls back to HTTP/2 (TCP port 7844).
- `quic`: Enforces QUIC transport exclusively (UDP 7844).
- `http2`: Enforces HTTP/2 transport over TLS exclusively (TCP 7844).
*(Note: legacy `h2mux` is obsolete and automatically upgraded to `http2`).*

---

## DNS

### Public Hostname Routing
To route public eyeball traffic to a tunnel:
1. A DNS `CNAME` record must be created for the desired hostname:
   `app.example.com` -> `<tunnel-uuid>.cfargotunnel.com`
2. **`proxied: true` Requirement**: The CNAME record **must** have Cloudflare proxying enabled (`proxied: true` / orange-clouded).
   - If unproxied (`proxied: false`), DNS resolves directly to `cfargotunnel.com` IP addresses which reject direct eyeball connections without the Cloudflare Edge SNI pipeline.

### DNS Record API Schema
- **Endpoint**: `POST /zones/{zone_id}/dns_records`
- **Fields**:
  ```json
  {
    "type": "CNAME",
    "name": "app.example.com",
    "content": "<tunnel-uuid>.cfargotunnel.com",
    "proxied": true,
    "ttl": 1,
    "comment": "managed-by:flareway gateway:prod-gw",
    "tags": ["flareway", "gateway:prod-gw"]
  }
  ```
- **Ownership Marking**:
  - `comment`: Up to 100 UTF-8 characters. Suitable for storing ownership markers (e.g. `flareway.io/owned-by: default/prod-gateway`).
  - `tags`: Set of string keywords (e.g. `["flareway", "env:prod"]`). Highly suitable for efficient filtering and reconciliation without parsing comments.

### Wildcard Support & Certificate Boundaries
- A DNS CNAME can target wildcards: `*.example.com` -> `<tunnel-uuid>.cfargotunnel.com`.
- **Universal SSL**: Automatically issues edge certificates for apex (`example.com`) and single-level subdomains (`*.example.com`).
- **Multi-Level Subdomain Boundary**: Universal SSL **cannot** cover multi-level hostnames (e.g. `*.api.example.com` or `dev.app.example.com`). Exposing multi-level hostnames via tunnel requires purchasing **Advanced Certificate Manager (ACM)** to generate custom/dedicated edge certificates, or restricting hostnames to single-level subdomains.

### `cloudflared tunnel route dns` Mechanism
The CLI command `cloudflared tunnel route dns <tunnel-id> <hostname>`:
1. Determines the authoritative Cloudflare Zone ID for `<hostname>`.
2. Checks for existing DNS records with matching `name`.
3. Calls the Cloudflare DNS API to create or overwrite a CNAME record pointing to `<tunnel-id>.cfargotunnel.com` with `proxied: true` and `ttl: 1`.

---

## Private networking

Cloudflare Zero Trust enables private routing (non-routable RFC1918 IPs and internal hostnames) through tunnels using WARP and Gateway.

### WARP Routing Flag
To activate packet routing inside `cloudflared`, remote configuration must enable:
```json
{
  "config": {
    "warp-routing": {
      "enabled": true
    }
  }
}
```

### Teamnet CIDR Routes API
- **Endpoint**: `POST /accounts/{account_id}/teamnet/routes`
- **Request Body**:
  ```json
  {
    "network": "10.244.0.0/16",
    "tunnel_id": "<tunnel_uuid>",
    "virtual_network_id": "<vnet_uuid>",
    "comment": "Kubernetes Pod CIDR"
  }
  ```
- **Virtual Networks**:
  - Endpoint: `POST /accounts/{account_id}/teamnet/virtual_networks`
  - Body: `{"name": "k8s-cluster", "is_default_network": false, "comment": "Flareway Cluster"}`
  - Prevents IP collision across overlapping subnets (e.g. two VPCs each using `10.0.0.0/16`).

### Private Hostname Routes (GA)
- **Status**: **Generally Available (GA)**. Integrated into Cloudflare Zero Trust APIs, OpenAPI specs, and Terraform provider v5.
- **Endpoint**: `POST /accounts/{account_id}/zerotrust/routes/hostname`
- **Request Body**:
  ```json
  {
    "hostname": "backend.corp.internal",
    "tunnel_id": "<tunnel_uuid>",
    "comment": "Internal API private hostname"
  }
  ```
- **Functionality**:
  - Allows routing a private domain name directly to a tunnel without declaring an underlying IP CIDR range.
  - WARP client users resolving `backend.corp.internal` are steered across the Cloudflare edge directly into the targeted tunnel.
  - Counted under the account-wide route quota: `"Routes (CIDR routes + Hostname routes) per account: 1,000"`.

---

## Edge limits (timeouts, body size, websockets/SSE)

| Limit / Feature | Value / Threshold | Behavior & Mitigation |
| :--- | :--- | :--- |
| **Edge Response Header Timeout** | **100 seconds** (Default) | If origin does not send initial response headers within 100s, edge terminates request with **HTTP 524 A Timeout Occurred**. Enterprise accounts can increase up to 6,000s via custom origin rules. |
| **HTTP Request Body Size Limit** | **Free / Pro**: 100 MB<br>**Business**: 200 MB<br>**Enterprise**: 500 MB (upgradable) | Edge rejects larger payloads with **HTTP 413 Payload Too Large**. Payloads bypass this restriction if routed via Private Network (WARP) routes instead of Public Hostnames. |
| **WebSockets** | Supported on all plans | No maximum connection duration. Cloudflare closes idle WebSocket sessions after **100 seconds** of inactivity. Origins or clients must implement periodic ping/pong frames (<100s). |
| **Server-Sent Events (SSE) / Chunked Streaming** | Supported | Cloudflare edge buffers HTTP responses by default. Origins serving SSE or long streams must send header `X-Accel-Buffering: no` or flush chunks immediately to prevent edge buffering stalls. |
| **TCP / Origin Connection Pool** | Default `keepAliveConnections: 100` | Governs idle pool size; concurrent in-flight streams multiplex over QUIC/HTTP2 with no artificial connection cap beyond host memory/CPU. |

---

## SDK / Terraform type map

To assist Flareway controller implementation in Go and Terraform provisioning, below are the exact type and package coordinates as of September 2026.

### Go SDK: `github.com/cloudflare/cloudflare-go/v7`

| Purpose / Concept | Go Package Path | Primary Go Struct / Type |
| :--- | :--- | :--- |
| **Tunnel CRUD** | `zero_trust` | `zero_trust.TunnelCloudflaredService`<br>`zero_trust.TunnelCloudflaredNewParams`<br>`zero_trust.TunnelCloudflaredDeleteParams`<br>`zero_trust.TunnelCloudflaredListParams` |
| **Tunnel Token** | `zero_trust` | `zero_trust.TunnelCloudflaredTokenGetParams` |
| **Tunnel Remote Configuration** | `zero_trust` | `zero_trust.TunnelCloudflaredConfigurationService`<br>`zero_trust.TunnelCloudflaredConfigurationUpdateParams`<br>`zero_trust.TunnelCloudflaredConfigurationUpdateParamsConfig`<br>`zero_trust.TunnelCloudflaredConfigurationUpdateParamsConfigIngress`<br>`zero_trust.TunnelCloudflaredConfigurationUpdateParamsConfigIngressOriginRequest`<br>`zero_trust.TunnelCloudflaredConfigurationUpdateParamsConfigIngressOriginRequestAccess` |
| **CIDR IP Routes (Teamnet)** | `zero_trust` | `zero_trust.NetworkRouteService`<br>`zero_trust.NetworkRouteNewParams`<br>`zero_trust.Route` |
| **Private Hostname Routes** | `zero_trust` | `zero_trust.NetworkHostnameRouteService`<br>`zero_trust.NetworkHostnameRouteNewParams`<br>`zero_trust.HostnameRoute` |
| **Virtual Networks** | `zero_trust` | `zero_trust.NetworkVirtualNetworkService`<br>`zero_trust.NetworkVirtualNetworkNewParams`<br>`zero_trust.VirtualNetwork` |
| **DNS Record CRUD** | `dns` | `dns.RecordService`<br>`dns.RecordNewParams`<br>`dns.RecordUpdateParams`<br>`dns.RecordDeleteParams` |

### Terraform Provider Cloudflare v5

| Resource / Data Source | Terraform Resource Name | Key Attributes / Schema |
| :--- | :--- | :--- |
| **Cloudflare Tunnel** | `cloudflare_zero_trust_tunnel_cloudflared` | `account_id` (req), `name` (req), `tunnel_secret` (opt), `config_src` (`"cloudflare"`) |
| **Tunnel Token (Data Source)** | `cloudflare_zero_trust_tunnel_cloudflared_token` | `account_id` (req), `tunnel_id` (req), `token` (computed) |
| **Tunnel Configuration** | `cloudflare_zero_trust_tunnel_cloudflared_config` | `account_id` (req), `tunnel_id` (req), `config.ingress` (list), `config.origin_request` |
| **CIDR Route** | `cloudflare_zero_trust_tunnel_cloudflared_route` | `account_id` (req), `tunnel_id` (req), `network` (req, CIDR), `virtual_network_id` (opt) |
| **Virtual Network** | `cloudflare_zero_trust_tunnel_cloudflared_virtual_network` | `account_id` (req), `name` (req), `is_default_network` (opt) |
| **DNS Record** | `cloudflare_dns_record` | `zone_id` (req), `name` (req), `type` (`"CNAME"`), `content` (`"<uuid>.cfargotunnel.com"`), `proxied` (`true`), `ttl` (`1`), `comment`, `tags` |

---

## Protect with Access vs originRequest.access & Infrastructure Access

1. **Dashboard "Protect with Access" vs `originRequest.access`**:
   - They refer to the **identical underlying API field**.
   - When an administrator toggles "Protect with Access" in the Cloudflare Zero Trust Dashboard for a public hostname, the UI automatically creates/links a Cloudflare Access Application and populates `config.ingress[].originRequest.access` with `required: true`, the account's `teamName`, and the application's `audTag: ["<aud>"]`.
   - In Flareway, attaching an Access Policy via Gateway API Policy Attachment (GEP-713) translates directly into generating this `originRequest.access` block on the ingress rule.
2. **Access for Infrastructure (SSH / TCP Targets)**:
   - For non-HTTP protocols (SSH, RDP, arbitrary TCP), Cloudflare provides "Access for Infrastructure" (target endpoints registered under Access).
   - In this mode, users connect via the `cloudflared access ssh --hostname <host>` client or browser-rendered terminal. The authentication handshake occurs at Cloudflare Edge and is proxied through `cloudflared` over an encrypted WebSocket tunnel (`proxyType: ""` or `"socks"`). Local Access JWT validation inside `cloudflared` does not apply to these stream proxies.

---

## Sources

- Cloudflare Tunnel Documentation: `https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/`
- Cloudflare Tunnel Remote API Guide: `https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/get-started/create-remote-tunnel-api/`
- Cloudflare Tunnel Origin Parameters: `https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/configure-tunnels/origin-parameters/`
- Cloudflare One Account Limits: `https://developers.cloudflare.com/cloudflare-one/account-limits/`
- Cloudflare Tunnels FAQ: `https://developers.cloudflare.com/cloudflare-one/faq/cloudflare-tunnels-faq/`
- `cloudflared` GitHub Repository: `https://github.com/cloudflare/cloudflared`
  - `ingress/ingress.go` (Host matching, regex pathing, catch-all validation, service protocols)
  - `ingress/config.go` (OriginRequestConfig, RemoteConfig schema, defaults)
  - `ingress/middleware/jwtvalidator.go` (Cf-Access-Jwt-Assertion validation, OIDC remote keyset)
  - `orchestration/orchestrator.go` (Tunnelrpc push updates, copy-on-write proxy swap)
  - `connection/protocol.go` (QUIC / HTTP2 edge transport protocol negotiation)
  - `metrics/metrics.go` & `metrics/readiness.go` (/ready, /metrics, /healthcheck server)
- `cloudflare-go` v7 SDK: `https://github.com/cloudflare/cloudflare-go`
  - `zero_trust/tunnelcloudflared.go`
  - `zero_trust/tunnelcloudflaredconfiguration.go`
  - `zero_trust/networkhostnameroute.go`
  - `zero_trust/networkroute.go`
  - `zero_trust/networkvirtualnetwork.go`
- `terraform-provider-cloudflare` v5: `https://github.com/cloudflare/terraform-provider-cloudflare`

---

## Open questions / gaps

1. **Hard Ingress Rule Count Limit**: Cloudflare documentation states account-wide tunnel and route limits (1,000 each) but does not publish a documented maximum number of ingress rules per tunnel. In practice, limits are constrained by Cloudflare API request body payload limits (~1-2 MB, corresponding to ~2,000–5,000 rules).
2. **Private Hostname Route Propagation Latency**: While public hostname tunnel ingress updates push in <2 seconds over `tunnelrpc`, private hostname routes (`/zerotrust/routes/hostname`) depend on Cloudflare Gateway DNS cache propagation across edge data centers for WARP clients, which can take 10–30 seconds.
3. **Automated Advanced Certificate Provisioning via API**: If a user specifies a multi-level public hostname (`a.b.domain.com`), Universal SSL will fail. It remains an orchestrator design question whether Flareway should auto-provision ACM dedicated certificates or reject multi-level hostnames during admission control.
