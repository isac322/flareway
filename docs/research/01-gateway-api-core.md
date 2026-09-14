# Kubernetes Gateway API Research Report (v1.6.2)

## Summary (10 bullets max)
- **Current releases**: As of 2026-09-12, the latest release is **v1.6.2** (released 2026-09-03, commit `ca6c2a6`); previous minor was **v1.5.1** (2026-03-14) / **v1.5.0** (2026-02-27), and previous patch was **v1.6.1** (2026-07-16).
- **Kubernetes 1.35 compatibility**: Gateway API v1.6 explicitly tests and supports Kubernetes **v1.32.0 through v1.36.0** (including **v1.35.0**), guaranteeing support for the 5 most recent minor releases.
- **Protocol route graduation**: `TLSRoute` graduated to `v1` (Standard) in v1.5.0; `TCPRoute` and `UDPRoute` graduated to `v1` (Standard) in v1.6.0; `GRPCRoute` graduated to `v1` (Standard) in v1.1.0; `HTTPRoute` has been `v1` (Standard) since v1.0.0.
- **Modular listeners**: `ListenerSet` (`gateway.networking.k8s.io/v1`) graduated to Standard in v1.5.0, obsoleting and removing experimental `XListenerSet`.
- **Backend TLS & Load Balancing policies**: `BackendTLSPolicy` graduated to `v1` (Standard) in v1.4.0; `BackendLBPolicy` was renamed and merged into `XBackendTrafficPolicy` (`gateway.networking.x-k8s.io/v1alpha1`, Experimental) in v1.3.0.
- **HTTPRoute filtering**: Core filters remain `RequestHeaderModifier` and `RequestRedirect`; Extended filters include `ResponseHeaderModifier`, `URLRewrite`, `RequestMirror`, and `CORS` (graduated to Standard in v1.5/v1.6); `ExternalAuth` (GEP-1494) is actively Experimental.
- **Policy attachment state**: GEP-713 is the governing specification; attempts to split it into GEP-2648 (Direct) and GEP-2649 (Inherited) were declined and merged back into GEP-713. CRD label convention is `gateway.networking.k8s.io/policy: Direct|Inherited`.
- **Handling unsupported route features**: Controllers reject unsupported enum values with `Accepted: False` (`Reason: UnsupportedValue`); if only a subset of rules is invalid, controllers set `PartiallyInvalid: True` (`Reason: UnsupportedValue`) and either drop invalid rules or fall back to the last known good generation.
- **Cloud edge addresses**: Gateway `status.addresses` supports `type: Hostname` (e.g., `<tunnel-id>.cfargotunnel.com`) in addition to `IPAddress`, and all intersected hostnames must route to these addresses.
- **Cloud edge conformance track record**: No cloud edge or tunnel provider (ngrok, Cloudflare, Tailscale, inlets, Akamai) has ever submitted a conformance report to the upstream Gateway API repository.

---

## Versions
- **Latest release**: `v1.6.2` (Release date: September 3, 2026; Git commit: `ca6c2a6`).
- **Immediate previous release**: `v1.6.1` (Release date: July 16, 2026).
- **Previous minor releases**: `v1.5.1` (Release date: March 14, 2026); `v1.5.0` (Release date: February 27, 2026).
- **Kubernetes 1.35 compatibility**: Both `v1.6.x` and `v1.5.x` are fully compatible with Kubernetes 1.35. The upstream CI validation matrix explicitly validates against `[v1.36.0, v1.35.0, v1.34.1, v1.33.0, v1.32.0]`. Gateway API upstream policy commits to supporting a minimum of the 5 most recent Kubernetes minor versions.
- **Sources**:
  - https://github.com/kubernetes-sigs/gateway-api/releases/tag/v1.6.2
  - https://github.com/kubernetes-sigs/gateway-api/blob/v1.6.2/CHANGELOG/1.6-CHANGELOG.md
  - https://github.com/kubernetes-sigs/gateway-api/blob/v1.6.2/site/content/en/docs/concepts/versioning.md

---

## Resource model

| Resource | Key Fields | Channel | Since Version | Group / Version |
| :--- | :--- | :--- | :--- | :--- |
| **GatewayClass** | `spec.controllerName`, `spec.parametersRef`, `spec.description` | **Standard** | v1.0.0 | `gateway.networking.k8s.io/v1` |
| **Gateway** | `spec.gatewayClassName`, `spec.listeners` (`name`, `port`, `protocol`, `hostname`, `tls`, `allowedRoutes`), `spec.addresses`, `spec.infrastructure` (`labels`, `annotations`, `parametersRef`), `spec.allowedListeners`, `spec.tls` (`backend`, `frontend`), `spec.defaultScope` | **Standard** (infrastructure Standard since v1.4.0/v1.5.0; backendTLS Standard in v1.5.0) | v1.0.0 | `gateway.networking.k8s.io/v1` |
| **ListenerSet** | `spec.parentRef`, `spec.listeners` (same schema as Gateway listeners) | **Standard** | v1.5.0 (GEP-1713) | `gateway.networking.k8s.io/v1` |
| *XListenerSet* | *Predecessor to ListenerSet; removed and obsoleted upon ListenerSet graduation* | *Removed* | v1.3.0–v1.4.1 | `gateway.networking.x-k8s.io/v1alpha1` |
| **HTTPRoute** | `spec.parentRefs` (`sectionName`, `port`), `spec.hostnames`, `spec.rules` (`name`, `matches`, `filters`, `backendRefs`, `timeouts`, `retry`, `sessionPersistence`) | **Standard** (Core: rules, matches, headers, weights; Extended: path rewrite, query params, method, timeouts, CORS; Experimental: retry, sessionPersistence, externalAuth) | v1.0.0 | `gateway.networking.k8s.io/v1` |
| **GRPCRoute** | `spec.parentRefs`, `spec.hostnames`, `spec.rules` (`matches`, `filters`, `backendRefs`, `timeouts`, `sessionPersistence`) | **Standard** | v1.1.0 | `gateway.networking.k8s.io/v1` |
| **TLSRoute** | `spec.parentRefs`, `spec.hostnames`, `spec.rules` (`backendRefs`) | **Standard** (`v1` Standard; `v1alpha2` deprecated) | v1.5.0 (GEP-2643) | `gateway.networking.k8s.io/v1` |
| **TCPRoute** | `spec.parentRefs`, `spec.rules` (`backendRefs`) | **Standard** (`v1` Standard; `v1alpha2` deprecated) | v1.6.0 (GEP-2645) | `gateway.networking.k8s.io/v1` |
| **UDPRoute** | `spec.parentRefs`, `spec.rules` (`backendRefs`) | **Standard** (`v1` Standard; `v1alpha2` deprecated) | v1.6.0 (GEP-2645) | `gateway.networking.k8s.io/v1` |
| **ReferenceGrant** | `spec.from` (`group`, `kind`, `namespace`), `spec.to` (`group`, `kind`, `name`) | **Standard** (`v1` since v1.5.0; `v1beta1` since v0.6.0) | v1.5.0 | `gateway.networking.k8s.io/v1` |
| **BackendTLSPolicy** | `spec.targetRefs` (`group`, `kind`, `name`, `sectionName`), `spec.validation` (`caCertificateRefs`, `wellKnownCACertificates`, `hostname`), `spec.options` | **Standard** (extended to multiple route types in v1.6.0) | v1.4.0 (GEP-1897) | `gateway.networking.k8s.io/v1` |
| **XBackendTrafficPolicy** | `spec.targetRefs`, `spec.retryConstraint` (`budget`), `spec.sessionPersistence` | **Experimental** | v1.3.0 | `gateway.networking.x-k8s.io/v1alpha1` |
| *BackendLBPolicy* | *Predecessor for session persistence; renamed/merged into XBackendTrafficPolicy* | *Obsoleted/Removed* | v1.1.0–v1.2.1 | `gateway.networking.k8s.io/v1alpha2` |
| **XBackend** | Backend abstraction for external or custom backends | **Experimental** | v1.6.0 (GEP-3467) | `gateway.networking.x-k8s.io/v1alpha1` |

### Key Field Specifics
- **Gateway.listeners.tls**:
  - `mode`: `Terminate` (default for HTTPS) or `Passthrough` (for TLS).
  - `certificateRefs`: list of `SecretObjectReference` (Core support: 1 secret in same namespace; cross-namespace requires `ReferenceGrant`).
  - `options`: `map[AnnotationKey]AnnotationValue` for domain-prefixed implementation extensions (e.g. min TLS version).
- **HTTPRoute.rules[].matches**:
  - `path.type`: `Exact` (Core), `PathPrefix` (Core), `RegularExpression` (Implementation-specific).
  - `headers`: `name`, `value`, `type: Exact|RegularExpression` (Exact is Core).
  - `queryParams`: `name`, `value`, `type: Exact|RegularExpression` (Exact is Extended).
  - `method`: HTTP method (Extended).
- **HTTPRoute.rules[].filters**:
  - `RequestHeaderModifier`: Core.
  - `ResponseHeaderModifier`: Extended.
  - `RequestRedirect`: Core.
  - `URLRewrite`: Extended.
  - `RequestMirror`: Extended.
  - `CORS`: Extended (graduated to Standard channel in v1.5.0/v1.6.0).
  - `ExtensionRef`: Implementation-specific (`group`, `kind`, `name`).
  - `ExternalAuth`: Extended, Experimental channel (GEP-1494).
- **HTTPRoute.rules[].timeouts**: `request` and `backendRequest` durations (Extended, Standard channel).
- **HTTPRoute.rules[].retry**: `codes`, `attempts`, `backoff` (Extended, Experimental channel).
- **HTTPRoute.rules[].sessionPersistence**: `sessionName`, `type: Cookie|Header`, `cookieConfig` (Extended, Experimental channel).

---

## Status conditions and reasons

### 1. GatewayClass Conditions (`GatewayClassConditionType`)
- **`Accepted`**:
  - `Accepted`: Successfully accepted by controller.
  - `InvalidParameters`: Referenced `parametersRef` invalid, unsupported, or malformed.
  - `Pending`: Not yet reconciled.
  - `Unsupported`: Controller does not support configuration.
  - `Waiting`: Waiting for controller prerequisites.
- **`SupportedVersion`**:
  - `SupportedVersion`: Installed CRD bundle version supported.
  - `UnsupportedVersion`: Installed CRD bundle version not supported.

### 2. Gateway Conditions (`GatewayConditionType`)
- **`Accepted`**:
  - `Accepted`: Gateway configuration is syntactically and semantically valid.
  - `ListenersNotValid`: Gateway contains one or more conflicted or invalid listeners.
  - `Pending`: Controller has not finished reconciling.
  - `UnsupportedAddress`: Requested address cannot be assigned.
  - `InvalidParameters`: `infrastructure.parametersRef` cannot be resolved or is invalid.
- **`Programmed`**:
  - `Programmed`: Gateway data plane configuration has been successfully generated and applied.
  - `Invalid`: Configuration cannot be programmed.
  - `Pending`: Data plane configuration in progress.
  - `AddressNotAssigned`: Gateway lacks required external address.
  - `AddressNotUsable`: Assigned address cannot be bound.
  - `NoResources`: Infrastructure resources exhausted.
- **`ResolvedRefs`**:
  - `ResolvedRefs`: All referenced objects (parametersRef, client certs) resolved.
  - `InvalidClientCertificateRef`: Backend client certificate invalid or unresolvable.
  - `RefNotPermitted`: Cross-namespace reference forbidden by missing ReferenceGrant.
  - `ListenersNotResolved`: Subordinate listener references cannot be resolved.

### 3. Listener Conditions (`ListenerConditionType`)
- **`Accepted`**:
  - `Accepted`: Listener accepted.
  - `PortUnavailable`: Port cannot be allocated.
  - `UnsupportedProtocol`: Protocol not supported.
  - `NoValidCACertificate`: Missing or invalid client CA certificate.
  - `UnsupportedValue`: Unsupported setting on listener.
- **`Conflicted`**:
  - `HostnameConflict`: Hostname conflicts with another listener on same port/protocol.
  - `ProtocolConflict`: Conflicting protocols bound to same port.
  - `NoConflicts`: Listener has no conflicts (`Conflicted: False`).
- **`ResolvedRefs`**:
  - `ResolvedRefs`: Certificate and route references successfully resolved.
  - `InvalidCertificateRef`: Referenced TLS Secret does not exist or lacks `tls.crt`/`tls.key`.
  - `InvalidRouteKinds`: Unsupported Route kind requested in `allowedRoutes.kinds`.
  - `RefNotPermitted`: Cross-namespace certificate reference missing ReferenceGrant.
  - `InvalidCACertificateRef`: Referenced CA certificate object invalid or missing.
  - `InvalidCACertificateKind`: Unsupported CA certificate resource kind.
- **`Programmed`**:
  - `Programmed`: Listener active on data plane.
  - `Invalid`: Listener cannot be programmed.
  - `Pending`: Listener programming in progress.

### 4. HTTPRoute Parent Conditions (`RouteConditionType`)
Populated per attached parent under `status.parents[]`:
- **`Accepted`**:
  - `Accepted`: Route successfully accepted by parent.
  - `NotAllowedByListeners`: Gateway listener `allowedRoutes` excludes route's namespace or kind.
  - `NoMatchingListenerHostname`: No compatible listener whose hostname intersects with route's hostnames.
  - `NoMatchingParent`: ParentRef specifies `port` or `sectionName` that does not match any listener.
  - `UnsupportedValue`: An enum or field value is unsupported by the implementation.
  - `IncompatibleFilters`: Mutually exclusive filters configured (e.g. `URLRewrite` + `RequestRedirect`).
  - `Pending`: Controller has not yet reconciled the route.
- **`ResolvedRefs`**:
  - `ResolvedRefs`: All backendRefs and extensionRefs resolved.
  - `RefNotPermitted`: BackendRef references another namespace without an authorizing ReferenceGrant.
  - `InvalidKind`: BackendRef references an unknown or unsupported Group/Kind.
  - `BackendNotFound`: BackendRef target does not exist.
  - `UnsupportedProtocol`: Backend service specifies unsupported application protocol.
- **`PartiallyInvalid`**:
  - Condition `PartiallyInvalid: True` with `Reason: UnsupportedValue`.
  - Triggered when a route contains a mix of valid and invalid rules.
  - Controller must take one of two explicit standardized actions:
    1. **Drop Rule(s)**: Drop invalid rules; condition message must start with `"Dropped Rule"`; keep `Accepted: True`.
    2. **Fall Back**: Revert route to last known good generation; condition message must start with `"Fall Back"`; keep `Accepted: True` with observedGeneration set to the fallback generation.
  - If **all** rules are invalid: route is rejected with `Accepted: False` (`Reason: UnsupportedValue`).

---

## Required semantics

### 1. Hostname Intersection (Listener vs HTTPRoute)
- When both `Listener.hostname` and `HTTPRoute.hostnames` are specified, there must be a valid mathematical intersection for the route to attach.
- Exact matches must match identical strings.
- Wildcards (`*.example.com`) match single or multiple DNS labels to the left (`foo.example.com`, `bar.foo.example.com`).
- Intersection table:
  - Listener `foo.example.com` $\cap$ Route `foo.example.com` $\to$ `foo.example.com` (Match).
  - Listener `*.example.com` $\cap$ Route `foo.example.com` $\to$ `foo.example.com` (Match).
  - Listener `foo.example.com` $\cap$ Route `*.example.com` $\to$ `foo.example.com` (Match).
  - Listener `*.example.com` $\cap$ Route `*.example.com` $\to$ `*.example.com` (Match).
  - Listener `*.example.com` $\cap$ Route `*.foo.example.com` $\to$ `*.foo.example.com` (Match).
  - Listener `example.com` $\cap$ Route `*.example.com` $\to$ No match (empty intersection $\to$ Route rejected with `NoMatchingListenerHostname`).
- If a route specifies no hostnames, it inherits the Listener's hostname. If Listener specifies no hostname, all route hostnames match.

### 2. Route Matching Precedence & Ordering Rules
Implementations MUST prioritize rule matches across all attached routes using the following strict tie-breaking hierarchy:
1. **Path match type**: `Exact` takes precedence over `PathPrefix`.
2. **Path match length**: `PathPrefix` with largest number of characters.
3. **HTTP Method match**: Rule with Method match takes precedence over rule without.
4. **Header matches**: Largest number of header matches.
5. **Query param matches**: Largest number of query parameter matches.
*Note*: Precedence of `RegularExpression` path matches is implementation-specific.
If ties persist across different routes:
6. **Creation timestamp**: Oldest Route resource wins.
7. **Alphabetical order**: First in alphabetical order by `{namespace}/{name}`.
If ties persist within a single route:
8. **List order**: The first rule in the `rules` array wins.

### 3. Listener Conflicts
- Each listener in a set MUST have a unique combination of `(Port, Protocol, Hostname)`.
- HTTP/HTTPS/TLS listeners conflict if they share Port and Hostname.
- If an implementation supports TCP, any HTTP/HTTPS/TLS listener sharing a port with a TCP listener conflicts and **both MUST be rejected**.
- When listeners conflict, implementations MUST set `Conflicted: True` on the listener status and `ListenersNotValid` on Gateway status.
- Implementations **MUST NOT** pick a winner among indistinct listeners; all conflicted listeners must be excluded.

### 4. AllowedRoutes Namespace Selectors
`spec.listeners[].allowedRoutes.namespaces`:
- `from: Same` (default): Only routes in the same namespace as Gateway may attach.
- `from: All`: Routes from any namespace may attach.
- `from: Selector`: Only routes in namespaces matching `selector.matchLabels` or `matchExpressions` may attach.

### 5. ReferenceGrant Requirements
- Every cross-namespace reference (other than route parentRef attachment) **requires** a `ReferenceGrant` in the target namespace.
- **TLS Secrets**:
  - `ReferenceGrant.spec.from`: `group: gateway.networking.k8s.io`, `kind: Gateway`, `namespace: <gateway-ns>`.
  - `ReferenceGrant.spec.to`: `group: ""`, `kind: Secret`, optional `name`.
- **Cross-namespace Backends**:
  - `ReferenceGrant.spec.from`: `group: gateway.networking.k8s.io`, `kind: HTTPRoute` (or GRPCRoute/TCPRoute/UDPRoute/TLSRoute), `namespace: <route-ns>`.
  - `ReferenceGrant.spec.to`: `group: ""`, `kind: Service`, optional `name`.
- Without a valid grant, controller MUST set `ResolvedRefs: False` with `Reason: RefNotPermitted`.

### 6. Gateway Addresses for Cloud Edge Providers
- Defined in `spec.addresses` and populated in `status.addresses`.
- Supported types:
  - `IPAddress`: IPv4/IPv6 address.
  - `Hostname`: Fully-qualified domain name (e.g., `edge-tunnel-123.cfargotunnel.com` or cloud load balancer DNS name).
  - `NamedAddress`: Implementation-specific address reference.
- **Cloud Edge Semantics**: When the data plane is a cloud SaaS edge (such as Cloudflare Tunnel), `status.addresses` SHOULD be populated with `type: Hostname` pointing to the edge tunnel hostname or edge CNAME target. The Gateway API specification explicitly requires that all intersected hostnames represented in listeners MUST route traffic to the addresses listed in `status.addresses`.

---

## Extension mechanisms

### 1. GEP-713 Policy Attachment
- **Status**: Governing pattern for meta-resources (`geps/gep-713/index.md`).
- **Splits Declined**: GEP-2648 (Direct Policy Attachment) and GEP-2649 (Inherited Policy Attachment) were declined and merged back into GEP-713.
- **Classes**:
  - **Direct Policy Attachment**: Tightly coupled to exactly one target resource (`spec.targetRef` or `spec.targetRefs`). Does not flow down the hierarchy (e.g. `BackendTLSPolicy`, `XBackendTrafficPolicy`).
  - **Inherited Policy Attachment**: Attaches at higher hierarchy levels (GatewayClass or Gateway) and inherits down to child routes and backends with `defaults` and `overrides` stanzas.
- **TargetRef Fields**:
  - `LocalPolicyTargetReference`: `group`, `kind`, `name`.
  - `LocalPolicyTargetReferenceWithSectionName`: adds `sectionName` (targets Gateway listener, HTTPRoute rule name, or Service port).
  - Recommendation: policies should target standard resources (Gateway, ListenerSet, HTTPRoute, Service).
- **CRD Label**: `gateway.networking.k8s.io/policy: Direct` or `gateway.networking.k8s.io/policy: Inherited`.
- **Status Reporting**:
  - Uses `PolicyStatus` containing `ancestors []PolicyAncestorStatus`.
  - Each entry contains `ancestorRef` (identifying the parent Gateway/Route), `controllerName`, and `conditions []metav1.Condition`.
- **Conflict Resolution**:
  - For Direct policies on the same target: oldest creation timestamp wins; on tie, alphabetical by `{namespace}/{name}`. The losing policy receives `Accepted: False` (`Reason: Conflicted`).
  - For Inherited policies: higher-level policy is *established* unless overridden; merges follow defined strategy (Atomic defaults/overrides, Patch defaults/overrides).

### 2. ExtensionRef Filter
- Configured in `HTTPRoute.spec.rules[].filters[]` with `type: ExtensionRef`.
- Field: `extensionRef: { group, kind, name }` (`LocalObjectReference`).
- **Constraints**:
  - MUST NOT be used for standard core/extended features.
  - If the referenced object cannot be found or is unsupported, the filter **MUST NOT be skipped**; the request MUST receive an HTTP error (500 status code), preventing bypass of intended security filters.

### 3. ParametersRef
- `GatewayClass.spec.parametersRef`: Global controller settings. Can be cluster-scoped or namespace-scoped.
- `Gateway.spec.infrastructure.parametersRef`: Per-Gateway infrastructure settings (e.g., cloudflared replica count, tunnel credential secret).
- Recommended hierarchy: `GatewayClass` provides defaults, which are overridden by `Gateway.infrastructure.parametersRef`.

### 4. Custom BackendRef Kinds
- `HTTPRoute.spec.rules[].backendRefs[].group` and `kind` can reference custom resources (e.g., `cloudflare.com/v1alpha1 CloudflareWorker`, or `gateway.networking.x-k8s.io/v1alpha1 XBackend`).
- Signaling support:
  - Conformance and documentation.
  - Gateway listener `allowedRoutes.kinds` can allow custom route kinds.
  - If a controller encounters an unsupported backend kind, it MUST set `ResolvedRefs: False` with `Reason: InvalidKind`.

### 5. Annotations vs Policy Attachment
- Implementation-specific annotations MUST be domain-prefixed (e.g., `flareway.runbear.io/tunnel-name`). Unprefixed annotations are forbidden.
- Gateway API guidelines explicitly discourage using annotations for feature configuration, strongly recommending Policy Attachment (GEP-713) or ExtensionRef.
- **Reserved Annotations**:
  - `gateway.networking.k8s.io/bundle-version`: Indicates installed CRD release bundle (e.g. `v1.6.2`).
  - `gateway.networking.k8s.io/channel`: Indicates installed channel (`standard` or `experimental`).
  - `api-approved.kubernetes.io`: Upstream KEP approval annotation.

---

## Conformance

### 1. GatewayHTTP Profile Features
The `GatewayHTTPConformanceProfile` (`GATEWAY-HTTP`) evaluates implementations against:
- **Core Features** (Mandatory for all conformant HTTP implementations):
  - `Gateway`: Core Gateway listener binding, ports 80/443, IPAddress/Hostname publication.
  - `ReferenceGrant`: Cross-namespace reference validation.
  - `HTTPRoute`: PathPrefix/Exact routing, header matching, backend service routing, weighted splits, core filters (`RequestHeaderModifier`, `RequestRedirect`).
- **Extended Features** (Optional; claimed support tested if advertised):
  - `HTTPRouteHostRewrite`
  - `HTTPRoutePathRewrite`
  - `HTTPRouteResponseHeaderModification`
  - `HTTPRoutePortRedirect`, `HTTPRouteSchemeRedirect`, `HTTPRoutePathRedirect`
  - `HTTPRouteRequestMirror`, `HTTPRouteRequestMultipleMirrors`, `HTTPRouteRequestPercentageMirror`
  - `HTTPRouteQueryParamMatching`, `HTTPRouteMethodMatching`
  - `HTTPRouteDestinationPortMatching`, `HTTPRouteParentRefPort`
  - `HTTPRouteRequestTimeout`, `HTTPRouteBackendTimeout`
  - `HTTPRouteCORS`
  - `HTTPRoute303RedirectStatusCode`, `HTTPRoute307RedirectStatusCode`, `HTTPRoute308RedirectStatusCode`
  - `HTTPRouteRetry`, `HTTPRouteRetryBackendTimeout`, `HTTPRouteRetryConnectionError`
  - `GatewayHTTPListenerIsolation`, `GatewayHTTPSListenerDetectMisdirectedRequests`
  - `GatewayStaticAddresses`, `GatewayAddressEmpty`
  - `GatewayInfrastructurePropagation`
  - `BackendTLSPolicy` & `BackendTLSPolicySANValidation`

### 2. How the Suite Dispatches Traffic
- **Client Execution**: The conformance runner executes standard Go HTTP client requests via `roundtripper.CaptureRoundTrip()`.
- **Routability**: The suite **requires a network-routable address** from the test runner to the Gateway (`gwAddr = status.addresses[0]`).
- **Listener Port**: The test runner dials `gwAddr:<listener-port>` directly.
- **Core TLS**: HTTPS listeners on port 443 with `tls.mode: Terminate` are part of Core HTTPRoute conformance tests.

### 3. Submission Process for Conformance Reports
- Implementations run the test suite: `go test -v ./conformance -run TestConformance`.
- The suite automatically generates a standardized YAML report.
- The report must be submitted via a GitHub Pull Request to `conformance/reports/<version>/<project-name>/` containing:
  - `<channel>-<version>-<mode>-report.yaml`
  - `README.md` with table of contents and a mandatory reproducible guide.

### 4. Cloud-Edge Implementations in Conformance
- **Track record**: A thorough audit of all reports from `v0.7.1` through `v1.6.2` reveals that **no cloud-edge or tunnel implementation (ngrok, Cloudflare Tunnel, Tailscale, inlets, Akamai)** has ever submitted a conformance report to `kubernetes-sigs/gateway-api`.
- All conformant implementations to date (Envoy Gateway, Istio, Cilium, GKE Gateway, AWS LBC, NGINX Gateway Fabric, Traefik, Kong, Contour, Airlock, Varnish) run data planes accessible directly via cluster or VPC routable endpoints.
- For Flareway to achieve conformance, the test runner host must be able to reach Cloudflare Edge IPs, or an internal loopback/proxy tunnel must be available during CI.

---

## Edge-relevant recent features

1. **Gateway `spec.infrastructure` (v1.4 / v1.5 Standard)**:
   - Contains `labels`, `annotations`, and `parametersRef`.
   - Allows propagation of metadata and custom parameters to underlying tunnel pods (e.g. `cloudflared` DaemonSets/Deployments).
2. **`ListenerSet` (v1.5.0 Standard, GEP-1713)**:
   - Enables splitting Gateway listeners across teams or namespaces without mutating the root Gateway object.
   - Crucial for SaaS edge architectures where different teams define distinct hostnames/tunnels under a shared parent Gateway.
3. **`HTTPRoute.rules[].name` (v1.4+ Extended)**:
   - Adds an optional `SectionName` to each rule.
   - Enables direct policy attachments (such as auth or rate-limiting) to target a specific rule by name.
4. **CORS Filter (v1.5.0 / v1.6.0 Standard, GEP-1767)**:
   - Standardized `HTTPRouteFilterCORS` (`allowOrigins`, `allowMethods`, `allowHeaders`, `exposeHeaders`, `maxAge`, `allowCredentials`).
5. **External Authentication Filter (GEP-1494, Experimental)**:
   - `HTTPRouteFilterExternalAuth` (`protocol: HTTP | GRPC`, `backendRef`).
   - Allows offloading auth to an external service (Envoy `ext_authz` or HTTP 200 check) before forwarding to the backend. Highly relevant for integrating Cloudflare Access JWT validation.
6. **`BackendTLSPolicy` Maturity (v1.4.0 Standard, v1.6.0 Expansion)**:
   - Standardizes upstream TLS termination verification between Gateway/tunnel and backend pods with custom CA certificates or system trust.
7. **Timeouts & Retries**:
   - `timeouts.request` and `timeouts.backendRequest` are Standard (Extended).
   - `retry` is Experimental in v1.6.0, supporting status codes, attempts, and backoff.

---

## Sources
- https://gateway-api.sigs.k8s.io/
- https://github.com/kubernetes-sigs/gateway-api/blob/v1.6.2/site/content/en/docs/concepts/versioning.md
- https://github.com/kubernetes-sigs/gateway-api/blob/v1.6.2/site/content/en/docs/concepts/hostnames.md
- https://github.com/kubernetes-sigs/gateway-api/blob/v1.6.2/site/content/en/docs/concepts/traffic-matching.md
- https://github.com/kubernetes-sigs/gateway-api/blob/v1.6.2/site/content/en/docs/concepts/conformance.md
- https://github.com/kubernetes-sigs/gateway-api/blob/v1.6.2/site/content/en/docs/implementations/list.md
- https://github.com/kubernetes-sigs/gateway-api/blob/v1.6.2/geps/gep-713/index.md
- https://github.com/kubernetes-sigs/gateway-api/blob/v1.6.2/geps/gep-1494/index.md
- https://github.com/kubernetes-sigs/gateway-api/blob/v1.6.2/geps/gep-1713/index.md
- https://github.com/kubernetes-sigs/gateway-api/blob/v1.6.2/geps/gep-1897/index.md
- https://github.com/kubernetes-sigs/gateway-api/blob/v1.6.2/apis/v1/gateway_types.go
- https://github.com/kubernetes-sigs/gateway-api/blob/v1.6.2/apis/v1/httproute_types.go
- https://github.com/kubernetes-sigs/gateway-api/blob/v1.6.2/apis/v1/listenerset_types.go
- https://github.com/kubernetes-sigs/gateway-api/blob/v1.6.2/apis/v1/backendtlspolicy_types.go
- https://github.com/kubernetes-sigs/gateway-api/blob/v1.6.2/apis/v1/referencegrant_types.go
- https://github.com/kubernetes-sigs/gateway-api/blob/v1.6.2/apis/v1/policy_types.go
- https://github.com/kubernetes-sigs/gateway-api/blob/v1.6.2/conformance/reports/README.md

---

## Open questions / gaps
1. **Conformance Suite Execution over Cloudflare Edge**:
   - Because standard conformance tests require sending raw HTTP requests with specific test Host headers and paths to `status.addresses`, routing them through Cloudflare Edge requires automated DNS record creation, TLS edge cert provisioning, and may trigger Cloudflare WAF/rate limits during high-frequency test loops. An in-cluster test harness or mock edge tunnel runner might be necessary for local CI.
2. **Cloudflare Tunnel Ingress Rule Expressiveness vs HTTPRoute Matchers**:
   - Cloudflare Tunnel `config.ingress` supports `hostname` and path regexes matching an origin service. However, it does not natively support HTTP method matching, header matching, query param matching, or complex filter chains (like response header modification or url rewrite) purely in `cloudflared`. The orchestrator must determine whether an in-pod Envoy sidecar/daemon is required to satisfy Gateway API HTTP conformance.
3. **External Authentication Filter vs Cloudflare Access**:
   - GEP-1494 (`HTTPRouteFilterExternalAuth`) specifies a forward call to a gRPC/HTTP authorization server. Cloudflare Access operates at the Cloudflare Edge, injecting `Cf-Access-Jwt-Assertion` headers. Reconciling whether to represent Cloudflare Access as an `ExternalAuth` filter or as a Direct Policy Attachment (e.g. `CloudflareAccessPolicy` targeting HTTPRoute) remains a primary design decision.
