# ADR 0001: Gateway API on Cloudflare Tunnel

- Status: Accepted
- Date: 2026-09-13
- Scope: how Flareway maps Gateway API resources and its own `flareway.bhyoo.com/v1alpha1` CRDs onto Cloudflare Tunnel, Access, and WARP.

## Context

Kubernetes operators who publish services through Cloudflare have to coordinate
several remote systems: a Cloudflare Tunnel and its `cloudflared` connectors,
proxied DNS records, Access applications and policies that guard hostnames,
and WARP private routing for clients on the corporate network. Each system
exposes its own API with its own rules, and most of them are
account-global.

Cluster users already describe HTTP exposure with the Gateway API
(`GatewayClass`, `Gateway`, `HTTPRoute`). The Gateway API also defines where
implementations may extend it: `parametersRef`, policy attachment through
GEP-713 `targetRefs`, and implementation-specific keys in listener
`tls.options`. Flareway needs a model that:

- lets tenants expose services with standard Gateway API objects, with no
  Cloudflare-specific annotations;
- passes the upstream Gateway API conformance suite for the features it claims;
- lets platform owners decide which namespaces may use which hostnames, zones,
  exposures, and backends;
- never takes over, deletes, or silently re-opens Cloudflare objects it does
  not provably own;
- reaches private services over WARP, including services with no public
  hostname.

`cloudflared` alone cannot satisfy the Gateway API. Its ingress rules match
only a hostname and an unanchored Go regular expression on the path. They
have no header, method, or query matching, no weighted backends, and no
rewrite, redirect, or mirror filters. GatewayHTTP Core requires all of these.

The CRD fields named below are documented in the [API reference](../reference/api.md).
For a walkthrough of the resulting system, see
[How it works](../concepts/how-it-works.md).

## Decision

### Integration model

In Cloudflare mode, each Flareway-managed `Gateway` owns one Cloudflare
Tunnel and one data-plane Deployment. Its data-plane Pods run upstream
`cloudflared` and Envoy; conformance mode omits `cloudflared`, and a
Gateway with private listeners adds a CoreDNS sidecar. `cloudflared`
carries traffic from the Cloudflare edge into the Pod and enforces origin
JWT checks per hostname. Envoy implements `HTTPRoute`
semantics. The controller compiles every attached `HTTPRoute` into Envoy
configuration, delivered over Delta ADS/SDS, and into a single whole-object
`cloudflared` ingress configuration.

Traffic follows one of two paths:

- **Public path.** Client → Cloudflare edge TLS → Access (for protected
  hostnames) → tunnel → `cloudflared` ingress rule (hostname and anchored
  path) → an Envoy loopback listener for that protection domain → backend.
- **Private path (WARP).** The WARP client asks Cloudflare Gateway DNS for a
  private hostname and receives a synthetic IP. The edge resolves the hostname
  through the tunnel's virtual DNS service. `cloudflared` forwards that query
  to the Pod-local CoreDNS sidecar (`TUNNEL_DNS_RESOLVER_ADDRS=127.0.0.1:53`,
  `internal/dataplane/deployment.go:240`), which answers `127.0.0.1`.
  The edge then sends the L4 flow to `127.0.0.1:<listener port>`,
  `cloudflared` dials it, and Envoy terminates TLS on the port the Gateway
  listener declares and applies the same compiled routes.

In Cloudflare mode, Envoy listeners bind to `127.0.0.1` only, and a
Gateway with private listeners also runs a CoreDNS sidecar bound to
`127.0.0.1`. The exceptions are the private-listener Pod IP fallback (D13)
and conformance mode (D14).

The controller is split into feature groups that can be switched on and off
independently: gateway, access, private-network, device, and organization
(`cmd/main.go:112-121`). The shared `CloudflareAccount` controller runs
whenever any group is enabled.

### Key decisions

**D1. Envoy implements HTTPRoute; `cloudflared` only transports and checks
JWTs.** `cloudflared` stays upstream and unmodified. It routes by hostname and
anchored path to a loopback Envoy port and enforces
`originRequest.access{required, teamName, audTag}` on protected hostnames.
Envoy handles matching, filters, weights, mirrors, timeouts, and backend TLS.
Rationale: native `cloudflared` ingress cannot express GatewayHTTP Core, and
forking `cloudflared` would tie every release to a patched binary. Envoy is a
mature Gateway API data plane, so conformance comes from the same engine other
implementations use.

**D2. One Gateway, one Tunnel, one data-plane Deployment.** A Gateway's
`spec.infrastructure.parametersRef` may name a `CloudflareTunnel` in the same
namespace. If it is omitted, the controller creates `CloudflareTunnel/<gateway-name>`
with the Gateway as controller owner and `deletionPolicy: Delete`. This
requires `GatewayClassConfig.spec.accountRef`
(`internal/controller/gateway_cloudflare.go:294-332`). The tunnel records its
owner as an exact `gatewayRef` plus `gatewayUid` pair. Another Gateway that
references the same tunnel is not programmed and reports which Gateway UID owns
it. When the owner releases the tunnel, the old UID's `cloudflared` Deployment
is scaled to zero and drained before a successor UID can be recorded. A Gateway
recreated with the same name does not inherit the old UID.
Rationale: Cloudflare replaces tunnel configuration as a whole object, so it
needs exactly one writer. Binding the tunnel to one Gateway removes the need
for a cross-Gateway aggregator and gives each tunnel one owner.

**D3. Extend only through Gateway API extension points; read no annotations
from Gateway API resources.** Infrastructure settings use `parametersRef`
(`GatewayClassConfig` on the class, `CloudflareTunnel` on the Gateway). Access
uses GEP-713 policy attachment. The only listener extension key is
`tls.options["flareway.bhyoo.com/edge-tls-mode"]`. Rationale: the Gateway API
project discourages annotations for policy, and annotations bypass schema
validation and status reporting. Typed fields and policy CRDs report errors
through conditions.

**D4. Two Access application kinds.** `AccessApplication` is a GEP-713 Direct
policy (label `gateway.networking.k8s.io/policy: Direct`). It targets a
`Gateway` or `HTTPRoute`, optionally narrowed by `sectionName` and
`pathScope`, and compiles the target into Cloudflare destinations. It can also
carry typed private, MCP, and Worker destinations. Its types are `SelfHosted`,
`SSH`, `VNC`, `RDP`, `MCP`, and `ProxyEndpoint`.
`AccessStandaloneApplication` manages applications that do not attach to a
Gateway: `SaaS`, `Bookmark`, `Infrastructure`, `AppLauncher`, `WARP`, `BISO`,
`DashSSO`, and `MCPPortal`. Both kinds require `accountRef`, an immutable
PascalCase `type`, and exactly the variant block that matches the type.
Rationale: Gateway-bound applications derive their hostnames from routes and
need route status, while standalone applications have no route. Mixing both
in one kind would leave most fields meaningless for each use.

**D5. Origin JWT validation is on by default.** Every protected hostname gets
`cloudflared` origin JWT enforcement with the application's AUD tag and the
team name derived from the account's `auth_domain`. Envoy also validates the
`Cf-Access-Jwt-Assertion` header or `CF_Authorization` cookie with
`jwt_authn` against the team JWKS on every protected domain
(`internal/gatewayapi/access.go:689-703`, `internal/xds/translator/translator.go:735-794`).
Private listeners rely on the Envoy check alone because no `cloudflared`
middleware runs on the WARP path. `originJWT.mode: Disabled` is accepted only
when the namespace carries `flareway.bhyoo.com/allow-origin-jwt-disable: "true"`
(`internal/gatewayapi/access.go:39,204`). If the AUD or team name is not yet
known, the protected domain stays blocked. Rationale: without an origin check,
anyone who reaches the origin by another path bypasses Access. Blocking until
the AUD exists closes the window between creating a route and creating its
Access application.

**D6. Separate protection domains per hostname region.** Each protected region
of a hostname gets its own `cloudflared` ingress rule and its own Envoy
listener. By default these listeners bind to loopback. Public and protected
paths may share a hostname only when the public carve-out `Q` is disjoint from
the protected region `P`, or when `P` contains `Q`. In the second case
Flareway creates a more specific child "bypass" Access application for each
carve-out, and the carve-out must be listed in the grant's
`unprotectedHostnames` (`internal/gatewayapi/access.go:580`). Other overlaps are
rejected. When a later `HTTPRoute` would break an established proof, its
offending rule is dropped and reported as `PartiallyInvalid`. Rationale:
Cloudflare Access matches by hostname and path at the edge, and a single Envoy
listener cannot tell which Access decision a request passed. Separate listeners
make the edge decision visible to the origin.

**D7. DNS is a property of the tunnel.** There is no DNS CRD. For every
listener hostname, Flareway maintains a proxied CNAME to
`<tunnel-id>.cfargotunnel.com`; a wildcard listener gets a wildcard record.
Ownership is recorded in the record `comment`, signed with a cluster-local
HMAC key stored in the `flareway-ownership-key` Secret
(`internal/cloudflare/ownership.go:29-60`, `internal/ownership/ownership.go:34-41`).
`dns.mode: External` leaves records to external-dns. When the Gateway has at
least one public listener, `Gateway.status.addresses` publishes the tunnel
hostname. A Gateway with only private listeners publishes an empty list.
Rationale: a DNS record exists only to point a hostname at a tunnel, so a
separate CRD would duplicate listener data. DNS tags have per-account quotas
and must be created in advance, so the comment carries ownership instead.

**D8. Cloudflare owns edge TLS for public listeners; Envoy owns TLS for
private listeners.** A public HTTPS listener must not set `certificateRefs`
(`UnsupportedValue`, "edge-terminated listener must not reference
certificates"). Its only accepted `tls.options` key is
`flareway.bhyoo.com/edge-tls-mode` with value `Full` or `Strict`
(`internal/gatewayapi/translate.go:495-507`). Flareway does not change the
zone SSL mode. A private listener must be HTTPS with exactly one
`certificateRef` and no TLS options (`internal/gatewayapi/translate.go:448-476`).
Rationale: the Cloudflare edge terminates public TLS with its own
certificates, so a Kubernetes Secret on a public listener would never be
served. On the WARP path the flow reaches Envoy as raw TCP, so Envoy must
terminate TLS with a certificate the client trusts.

**D9. One CRD owns each account-global, whole-replacement API.** Device
profiles with their split-tunnel include, exclude, and fallback lists
(`DeviceProfile`), account device settings (`DeviceSettings`), and
organization settings (`ZeroTrustOrganization`) each have a single owning
CRD. Per-route reconcilers never call these APIs. Rationale: these APIs replace
the whole list or object on each write. Two writers would overwrite each
other, so one reconciler aggregates the desired state and writes once.

**D10. Ownership needs remote metadata, a status ID, and explicit adoption.**
Kinds that manage a remote object share
`managementPolicy: Managed | ObserveOnly` and
`deletionPolicy: Delete | Orphan`. A kind whose remote object has a durable
identifier also supports `externalRef` and
`adoption.mode: None | AdoptById`. The account singletons `DeviceSettings`
and `ZeroTrustOrganization` omit `externalRef` and adoption, and
`ZeroTrustOrganization` permits only `deletionPolicy: Orphan`; a
`DeviceProfile` of kind `Default` rejects `externalRef` and adoption too.
Consult each kind's schema for its exact lifecycle fields. A newly created
object is owned through its recorded remote ID and Flareway metadata (tags,
comment, or name prefix, depending on the Cloudflare object). An existing
object is taken over only with `AdoptById` and a matching `adoption.expect`.
A name match alone never transfers ownership. `ObserveOnly` reads and
reports but performs no remote or credential mutation. Rationale: Cloudflare
accounts are often shared with Terraform, the dashboard, or other clusters.
Silent adoption could delete or rewrite objects that belong to someone
else. See
[Ownership and adoption](../concepts/ownership-and-adoption.md).

The same ownership rule applies field by field. A mutable Cloudflare field
that a kind owns becomes a typed `spec` field, and server-owned values become
bounded `status`. A mutable field that belongs to a concern no Flareway kind
models, such as Access destination path overrides, rule-format target
selectors, or account-wide service-token policy, is excluded: Flareway never
sends or reads it, leaves it to other tooling, and does not detect drift on
it. The parity ledger records each such field
([API reference](../reference/api.md#parity-ledger-and-intentional-exclusions)).

**D11. `CloudflareAccount.spec.grants[]` defines the tenant boundary.** A
cluster-scoped `CloudflareAccount` holds the API token reference. Each grant
matches namespaces by label selector and lists allowed hostnames (exact,
single-label wildcard, or `*`), zones, exposures, unprotected hostnames,
backend namespaces and kinds, private-route selectors, and permission to
reference platform Access objects. A namespace that matches no grant is denied.
Policy CRs attach only to targets in their own namespace. Rationale: the API
token is account-wide, so the operator must enforce tenancy itself. Keeping
grants on the account puts that boundary in one object the platform team
controls. See [Security model](../concepts/security-model.md).

**D12. Conformance is verified in two separate layers.** The upstream
GatewayHTTP suite runs in `GatewayClassConfig.spec.conformanceMode: true`,
where Envoy is reached directly without the Cloudflare edge. Behavior that
depends on Cloudflare (hostnames, DNS, edge TLS, Access, origin JWT, WARP) is
tested separately against a real account. Neither result stands in for the
other. Rationale: the official fixtures use `*.example.com` and cannot run
through a real Cloudflare zone. Claiming conformance through the edge would
need a fake edge, while dropping the suite would leave Gateway API behavior
unverified.

**D13. Private hostnames resolve through a Pod-local DNS sidecar.** A
Gateway with at least one private listener runs a CoreDNS sidecar in its
data-plane Pod, bound to `127.0.0.1:53`. It answers private listener
hostnames (exact and single-label wildcard) with `127.0.0.1` and
forwards everything else to the Pod's resolver
(`internal/dataplane/dns.go:79-113`). If the edge does not accept a loopback
answer, a private listener can fall back to Pod IP binding. The sidecar then
answers with the Pod IP, Envoy binds the listener on `0.0.0.0`, a
NetworkPolicy restricts access, and the tunnel reports
`PrivateListenerDegraded=True` with reason `PodIPFallback`
(`internal/controller/gateway_private.go:394-406`). Rationale: `cloudflared`
dials the IP the edge sends and resolves hostnames through its DNS resolver
setting. `hostAliases` is invisible to that path, and changing cluster DNS
would affect every workload.

**D14. Conformance mode relaxes the Cloudflare constraints.** With
`conformanceMode: true`, listeners may use any hostname and port, HTTPS
listeners must reference certificates, and grant, edge-hostname, tunnel, DNS,
and Access checks do not apply. Envoy binds `0.0.0.0` on
`10000 + listener port` behind a Service that exposes the declared port
(`internal/gatewayapi/translate.go:431-434`). This mode cannot be combined with
an account. Rationale: the suite needs a reachable address and arbitrary
listeners, which the Cloudflare edge does not allow.

**D15. Delete in block-first order.** When a `CloudflareTunnel` is deleted,
Flareway first waits for the recorded Gateway UID to switch every hostname to
403. It then removes managed DNS records, scales that UID's `cloudflared`
Deployment to zero, and waits for its `AccessApplication` cleanup. A tunnel
that `NetworkRoute` or `HostnameRoute` objects still reference reports
`CleanupBlocked` and keeps its finalizer. Last, it evicts connections and
deletes the remote tunnel, or retains it under `deletionPolicy: Orphan`
(`internal/controller/cloudflaretunnel_controller.go:646-800`). Rationale:
removing Access or DNS before the data plane stops could leave a window in
which a protected origin is reachable without Access.

### User decisions

These decisions were made by the project owner rather than derived from
analysis.

- **U1. API group `flareway.bhyoo.com`.** Controller name
  `flareway.bhyoo.com/gateway-controller`
  (`internal/gatewayapi/features.go:27`).
- **U2. WARP and organization-wide settings are first-class.** Device
  profiles, device settings, posture, Gateway policies, lists, and
  organization settings are modeled as CRDs alongside Tunnel and Access
  instead of being left to the dashboard.
- **U3. Kind naming.** Only `CloudflareAccount` and `CloudflareTunnel` carry the
  `Cloudflare` prefix. The other 20 kinds use the Cloudflare product names
  (for example `IdentityProvider`, `VirtualNetwork`, `DeviceProfile`). Names
  that overlap with other projects do not collide because the API group
  differs.
- **U4. One Gateway, one Tunnel** (D2), with the implicit tunnel created when
  `parametersRef` is omitted.
- **U5. No DNS CRD** (D7). DNS settings live in `CloudflareTunnel.spec.dns`,
  with defaults from `GatewayClassConfig.spec.dns`.
- **U6. Exposure is a platform decision per listener.** The platform declares
  each listener `Public` or `Private` in `CloudflareTunnel.spec.listeners[]`.
  Tenants write an `HTTPRoute` and, for protection, one `AccessApplication`.
  One Gateway cannot expose the same hostname both publicly and privately; the
  tunnel reports "hostname exposure must be unique per Gateway"
  (`internal/controller/cloudflaretunnel_controller.go:1786`).
- **U7. Private L4 without a hostname is in scope.** `NetworkRoute` (CIDR) and
  `HostnameRoute` route private traffic to a tunnel or `WARPConnector`, and
  `AccessApplication.spec.destinations[]` has a typed `Private` variant that
  references them.
- **U8. Two-layer conformance** (D12).
- **U9. Pod-local DNS sidecar for private hostnames** (D13).

## Gateway API support

The supported features below are the list the controller publishes in
`GatewayClass.status.supportedFeatures` (`internal/gatewayapi/features.go:29-59`).
The [conformance report](../conformance/v1.6.3/flareway/README.md) for Gateway
API v1.6.3 (standard channel, GATEWAY-HTTP profile: Core 36/36, Extended 32/32)
covers every one of them.

| Area | Status |
|---|---|
| Core: `Gateway`, `HTTPRoute`, `ReferenceGrant` | Supported |
| `BackendTLSPolicy`, `BackendTLSPolicySANValidation` | Supported |
| `GatewayHTTPListenerIsolation`, `GatewayHTTPSListenerDetectMisdirectedRequests`, `GatewayInfrastructure` | Supported |
| `HTTPRouteHostRewrite`, `HTTPRoutePathRewrite`, `HTTPRouteResponseHeaderModification` | Supported |
| `HTTPRoutePathRedirect`, `HTTPRoutePortRedirect`, `HTTPRouteSchemeRedirect`, `HTTPRoute303/307/308RedirectStatusCode` | Supported |
| `HTTPRouteMethodMatching`, `HTTPRouteQueryParamMatching`, `HTTPRouteParentRefPort` | Supported |
| `HTTPRouteDestinationPortMatching` | Supported; a route whose `parentRefs[].port` matches no listener reports `Accepted=False/NoMatchingParent` |
| `HTTPRouteRequestMirror`, `HTTPRouteRequestMultipleMirrors`, `HTTPRouteRequestPercentageMirror` | Supported |
| `HTTPRouteRequestTimeout`, `HTTPRouteBackendTimeout`, `HTTPRouteCORS` | Supported |
| `HTTPRouteBackendProtocolH2C`, `HTTPRouteBackendProtocolWebSocket` | Supported |
| `GatewayStaticAddresses`, `GatewayAddressEmpty` | Unsupported; any `spec.addresses` entry, with or without a value, is rejected with `UnsupportedAddress`. Cloudflare owns the edge addresses; a Gateway with a public listener reports the tunnel's `<tunnel-id>.cfargotunnel.com` hostname (D7) |
| `GatewayPort8080` | Unsupported |
| `HTTPRouteRetry`, `HTTPRouteRetryBackendTimeout`, `HTTPRouteRetryConnectionError` | Unsupported |
| `HTTPRouteBackendRequestHeaderModification`, `HTTPRouteNamedRouteRule` | Unsupported |
| `GatewayBackendClientCertificate`, `GatewayFrontendClientCertificateValidation`, `GatewayFrontendClientCertificateValidationInsecureFallback` | Unsupported |
| `ListenerSet` | Unsupported; `spec.allowedListeners` is rejected with `ListenersNotValid` |
| `GRPCRoute`, `TLSRoute`, `TCPRoute`, `UDPRoute` | Unsupported; listeners report `InvalidRouteKinds`. Use `NetworkRoute` for private L4 |
| `ExtensionRef` filters | Unsupported; the rule returns 500 and the route reports `ResolvedRefs=False/InvalidKind` |

Features are verified in conformance mode. On the Cloudflare edge, public
listeners accept only `HTTP/80` and `HTTPS/443`, and a redirect to another port
on a Flareway hostname reaches a port the edge does not serve. See
[Limits](../concepts/limits.md) and [HTTP routing](../concepts/http-routing.md).

## Consequences

### Positive

- Tenants use standard `Gateway` and `HTTPRoute` objects. The route behavior
  they get is the behavior the conformance suite checks.
- Protected hostnames fail closed: until the Access application, its AUD, and
  the origin JWT check are in place, the protection domain returns 403.
- Tenant access to hostnames, zones, exposures, backends, and platform objects
  is decided in one place per account.
- Flareway never modifies or deletes a remote object it did not create or
  explicitly adopt, so it can share an account with Terraform or other
  clusters.
- Every data-plane Pod is self-contained. Losing one Gateway's Pod does not
  affect other Gateways.

### Negative

- Each Gateway runs its own data-plane Pod (`cloudflared`, Envoy, and, for
  private listeners, CoreDNS) and uses its own tunnel. Many small Gateways
  cost more than one shared connector.
- Envoy adds a hop and a component to operate between `cloudflared` and the
  backend.
- A public hostname that mixes protected and unprotected paths needs a proof
  of disjointness or containment, and a bypass application per carve-out. Some
  route layouts that Cloudflare would accept are rejected.
- Access JWTs are stateless. Revoking a user's access takes effect at the
  edge, but a JWT already issued stays valid at the origin until it expires.
  The application `sessionDuration` bounds that window.
- The private path requires WARP, `DeviceSettings.gatewayProxyEnabled` and
  `gatewayUdpProxyEnabled`, a ready `VirtualNetwork`, a `HostnameRoute` that
  targets the tunnel, and Gateway TLS decryption when origin JWT is required
  (`internal/controller/gateway_private.go:83-122`).

### Limits

- Every listener must set a hostname. Public listeners accept only
  `HTTP/80` and `HTTPS/443` (`PortUnavailable` otherwise), and private
  listeners accept only `HTTPS` (`UnsupportedProtocol` otherwise)
  (`internal/gatewayapi/translate.go:384-450`).
- Gateway API wildcards match several labels (`*.example.com` matches
  `a.b.example.com`), but grant wildcards match exactly one label
  (`internal/authz/evaluate.go:235-255`). Universal SSL covers only the apex
  and one label below it, and Flareway does not check route hostname depth.
  Deeper hostnames need a certificate managed outside Flareway.
- Each tunnel belongs to one Gateway UID at a time. A second Gateway that
  references it stays unprogrammed until the owner releases it and its
  data plane drains.
- Experimental-channel resources and fields (retries, session persistence,
  `XBackendTrafficPolicy`, external auth) are out of scope.

## Alternatives considered

**Native `cloudflared` ingress only.** Rejected: it cannot express GatewayHTTP
Core matching or filters (D1).

**A forked or embedded L7 proxy inside `cloudflared`.** Rejected: it would
couple every release to a patched connector and still need a conformant router.

**Several Gateways sharing one tunnel through an aggregator.** Rejected:
whole-object tunnel configuration would need a cross-Gateway merge with its
own conflict rules and a single point of failure (D2).

**Annotations on Gateway API resources** for tunnel selection, origin
settings, DNS options, Access, and deletion policy. Rejected: each maps to a
typed extension point (`parametersRef`, `CloudflareTunnel.spec`,
`AccessApplication`, `deletionPolicy`, `CloudflareTunnel.spec.listeners[].exposure`),
and annotations carry no schema or status (D3).

**Cloudflare Access as an `HTTPRoute` `ExtensionRef` filter.** Rejected: Access
decides at the edge per hostname and path, before the request reaches any
route rule. Policy attachment matches that scope.

**A separate DNS CRD.** Rejected: it would duplicate listener hostnames and
add ordering between two objects (D7).

**DNS tags for ownership.** Rejected: tags have per-account quotas and must be
created in advance. The record comment has no such limits (D7).

**Adopting remote objects by name.** Rejected: names are not unique across
tools and clusters, so a name match could hand Flareway an object it must not
delete (D10).

**Private hostname resolution alternatives** (D13):

| Option | Reason rejected |
|---|---|
| Pod `hostAliases` | `cloudflared` resolves through the DNS resolver address, not `/etc/hosts`, so the hostname returns NXDOMAIN. |
| Cluster CoreDNS rewrite | Needs cluster-admin changes to shared DNS and affects every workload. |
| Cloudflare Gateway DNS override plus a CIDR route to the Service IP | Requires Service CIDR routing and breaks when the ClusterIP changes. |
| Service FQDN as the private hostname | Exposes internal names to clients; suitable only for development. |

**Separate private Envoy ports.** Rejected: the edge preserves the
destination port of the WARP flow, and Access private destinations use the
listener port as their `portRange`. A different Envoy port would break both.

**Running the conformance suite through the Cloudflare edge.** Rejected: the
suite's fixtures cannot use a real zone, and a mocked edge would prove nothing
about Cloudflare (D12).

## Related documents

- [How it works](../concepts/how-it-works.md)
- [HTTP routing](../concepts/http-routing.md)
- [Security model](../concepts/security-model.md)
- [Ownership and adoption](../concepts/ownership-and-adoption.md)
- [Limits](../concepts/limits.md)
- [Install](../get-started/install.md) and [Protect with Access](../get-started/protect-with-access.md)
- [API reference](../reference/api.md)
- [Gateway API v1.6.3 conformance report](../conformance/v1.6.3/flareway/README.md)
