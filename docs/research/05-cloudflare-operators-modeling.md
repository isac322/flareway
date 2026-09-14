# Architectural Research: Modeling Cloudflare Concepts in Kubernetes

*Date: 2026-09-12 | Scope: Comparative Analysis of Cloudflare Operators, Gateway API, Access, DNS, and Data Planes*

---

## Summary (10 bullets max)

1. **Attachment Paradigms**: Existing operators split cleanly into three attachment models: (a) Gateway API policy attachment with `targetRef`/`targetRefs` (`cfgate` Access & Origin policies), (b) Gateway API `parametersRef` on `GatewayClass` and `Gateway.spec.infrastructure` (`lexfrei`, `StringKe`), and (c) CRD bindings referencing target Services or annotations (`adyanth`, `STRRL`).
2. **Data Plane Divide**: Only `lexfrei` achieves Gateway API conformance (v1.6.1 conformant) by embedding an in-process L7 reverse proxy inside a custom `cloudflared` fork (`OverrideProxy` hook); all other operators (`cfgate`, `StringKe`, `adyanth`, `STRRL`) rely exclusively on native `cloudflared` ingress rules, restricting them to hostname + path regex routing without filters, header/query matching, or weighted multi-backend load balancing.
3. **Tunnel Single-Writer Problem**: Updating Cloudflare's whole-document Tunnel Configuration API is solved either by monolithic cluster-wide route aggregation per reconciliation loop (`cfgate`, `lexfrei`) or through an intermediate Kubernetes `ConfigMap` buffer where multiple controllers (Gateway, Ingress, TunnelBinding) register prioritized `SourceConfig` fragments reconciled by a dedicated `TunnelConfig Controller` (`StringKe`).
4. **Access Modeling**: `cfgate` models Zero Trust via decoupled account-level reusable policies (`CloudflareAccessPolicy`) bound to route host/path targets via `CloudflareAccessApplication` (`targetRef`), propagating AUD tags to status but not injecting them into `cloudflared` local validation; `StringKe` provides 6+ distinct Access CRDs (`AccessApplication`, `AccessPolicy`, `AccessGroup`, `AccessServiceToken`, etc.) configuring edge Zero Trust directly.
5. **DNS Separation vs Direct Sync**: `lexfrei` completely delegates DNS to `external-dns` by publishing `<tunnelID>.cfargotunnel.com` to `Gateway.status.addresses`; `cfgate` offers a standalone `CloudflareDNS` CRD with two-way sync, CNAME generation, and TXT ownership; `StringKe` supports tri-mode DNS (Automatic API, manual/external-dns, or managed `DNSRecord` CRDs); `STRRL` manages DNS directly but allows disabling via annotation.
6. **external-dns Cloudflare Provider**: The exact verified annotation keys in `kubernetes-sigs/external-dns` are `external-dns.alpha.kubernetes.io/cloudflare-proxied`, `cloudflare-custom-hostname`, `cloudflare-region-key`, `cloudflare-record-comment`, and `cloudflare-tags` (not `cloudflare-record-tags`). Its Gateway API source extracts hostnames intersecting Gateway listeners and sets targets from `Gateway.status.addresses`.
7. **DNS Ownership Model**: external-dns and `cfgate` avoid DNS CNAME/TXT collisions by prefixing ownership TXT records (`_external-dns.<hostname>` and `_cfgate.<hostname>`) storing serialized heritage, owner ID, and resource metadata.
8. **WARP / L4 Realities**: `cfgate` formally halted its v0.2.0 L4/WARP roadmap on 2026-04-12 (PR #4, issues #5/#12/#13/#16) after concluding that public TCP/UDP routing does not fit the free-tier Cloudflare Tunnel model (public TCP requires client-side `cloudflared access tcp`, public UDP requires Cloudflare Spectrum, and gRPC trailers are dropped over QUIC). `StringKe` supports private routing via `VirtualNetwork` and `NetworkRoute` CRDs.
9. **Origin Policies vs Annotations**: `cfgate` developed `CloudflareOriginPolicy` (PR #72) with strict 4-level precedence (`Tunnel.originDefaults` < `CloudflareOriginPolicy` < `BackendTLSPolicy` < Route Annotations) to replace annotation sprawl with GEP-713-style policy attachments.
10. **Licensing**: `cfgate` (Apache 2.0), `StringKe/cloudflare-operator` (Apache 2.0), `adyanth/cloudflare-operator` (Apache 2.0), `STRRL` (Apache 2.0), `kubernetes-sigs/external-dns` (Apache 2.0), and `lexfrei/cloudflare-tunnel-gateway-controller` (BSD 3-Clause).

---

## Per-Project Profiles

### 1. cfgate (`cfgate/cfgate`)

`cfgate` is a Kubernetes operator designed specifically around the Gateway API standard (v1.5.1+) to manage Cloudflare Tunnels, DNS records, Access policies, and Access application bindings.

#### CRD Inventory (`cfgate.io/v1alpha1`)
All CRDs are **Namespaced**.

| CRD Kind | Key Spec Fields | Key Status Fields | Attachment Mechanism |
|---|---|---|---|
| `CloudflareTunnel` | `tunnel.name`, `cloudflare.secretRef`, `cloudflare.accountId`, `cloudflared.replicas`, `cloudflared.image`, `originDefaults` (`connectTimeout`, `noTLSVerify`, `http2Origin`, `h2cOrigin`, `caPoolSecretRef`), `fallbackTarget` | `tunnelId`, `tunnelName`, `tunnelDomain`, `connectedRouteCount`, `conditions` | Bound to Gateway via `cfgate.io/tunnel-ref` annotation on the `Gateway` |
| `CloudflareDNS` | `tunnelRef.name`, `externalTarget`, `zones[]`, `policy` (`sync`, `upsert-only`, `create-only`), `source.gatewayRoutes.enabled`, `source.gatewayRoutes.annotationFilter`, `source.explicit[]`, `defaults.proxied`, `defaults.ttl`, `ownership.ownerId`, `ownership.txtRecord.prefix` | `managedRecordCount`, `syncedZones[]`, `conditions` | Watches `HTTPRoute` resources attached to Gateways that reference the linked `CloudflareTunnel` |
| `CloudflareAccessPolicy` | `cloudflareRef`, `name`, `decision` (`allow`, `deny`, `bypass`, `non_identity`), `include[]`, `exclude[]`, `require[]`, `sessionDuration`, `purposeJustificationRequired`, `approvalRequired`, `serviceTokens[]` | `policyId`, `serviceTokenSecretRefs[]`, `conditions` | Attached to routes via `CloudflareAccessApplication.spec.policyRefs` |
| `CloudflareAccessApplication` | `targetRef` (single) or `targetRefs[]` (Gateway or HTTPRoute), `cloudflareRef` (optional; inherits from Gateway/Tunnel), `application.name`, `application.domain`, `application.sessionDuration`, `policyRefs[]` (`name`, `namespace`, `precedence`) | `applicationId`, `observedApplications[]` (`id`, `aud`, `domain`, `targetRef`), `conditions` | GEP-713 direct target reference (`targetRef`/`targetRefs`) to `gateway.networking.k8s.io/HTTPRoute` or `Gateway` |
| `CloudflareOriginPolicy` (PR #72) | `targetRef` (`group: gateway.networking.k8s.io`, `kind: HTTPRoute`, `name`, `sectionName`), `origin` (`protocol`, `connectTimeout`, `noTLSVerify`, `http2Origin`, `h2cOrigin`, `caPoolSecretRef`, `httpHostHeader`, `originServerName`) | `conditions` (`Accepted`, `ResolvedRefs`), `observedGeneration` | GEP-713 policy attachment targeting `HTTPRoute` |

#### Annotations Read by cfgate

| Annotation Key | Applied Object | Value Format / Type | Purpose |
|---|---|---|---|
| `cfgate.io/tunnel-ref` | `Gateway` | `<namespace>/<name>` or `<name>` | Binds a Gateway to a `CloudflareTunnel` instance |
| `cfgate.io/tunnel-target` | `Gateway` | `{tunnelID}.cfargotunnel.com` | Output annotation populated by controller for DNS resolution |
| `cfgate.io/origin-protocol` | `HTTPRoute` | `http`, `https` (default: `http`) | Origin protocol dialed by cloudflared |
| `cfgate.io/origin-ssl-verify` | `HTTPRoute` | boolean (`true`, `false`) | Toggles origin TLS verification (`noTLSVerify` in cloudflared) |
| `cfgate.io/origin-connect-timeout` | `HTTPRoute` | Go duration (`30s`, `1m`) | Timeout for dialing origin TCP connection |
| `cfgate.io/origin-http-host-header` | `HTTPRoute` | Hostname string | Overrides HTTP `Host` header sent to origin |
| `cfgate.io/origin-server-name` | `HTTPRoute` | Hostname string | TLS SNI hostname sent during origin TLS handshake |
| `cfgate.io/origin-ca-pool` | `HTTPRoute` | `/etc/cfgate/origin-ca-pool/ca.pem` | Path to mounted custom CA bundle |
| `cfgate.io/origin-http2` | `HTTPRoute` | boolean (`true`, `false`) | Enables HTTP/2 origin transport for HTTPS origins |
| `cfgate.io/origin-h2c` | `HTTPRoute` | boolean (`true`, `false`) | Enables cleartext HTTP/2 (h2c) origin transport (inherent-design fork) |
| `cfgate.io/ttl` | `HTTPRoute` | Integer `1`-`86400` (`1` = auto) | DNS TTL for records generated from this route |
| `cfgate.io/cloudflare-proxied` | `HTTPRoute` | boolean (`true`, `false`) | Toggles Cloudflare orange-cloud proxying for DNS record |
| `cfgate.io/hostname` | `HTTPRoute` | RFC 1123 hostname | Overrides `spec.hostnames` on HTTPRoute |
| `cfgate.io/access-policy` | `HTTPRoute` | `<name>` or `<ns>/<name>` | *Deprecated:* Status-only policy reference |
| `cfgate.io/deletion-policy` | All cfgate CRDs | `orphan` | Skips remote Cloudflare resource deletion on CR deletion |
| `cfgate.io/allow-deep-subdomains` | `CloudflareDNS` | boolean (`true`) | Suppresses warning event for multi-level subdomains |
| `cfgate.io/config-hash` | `CloudflareTunnel` | SHA-256 string | Internal annotation caching last-synced tunnel configuration |

#### Ownership and Adoption
- **Tunnel Adoption**: `CloudflareTunnel.spec.tunnel.name` checks Cloudflare API. If a tunnel with that name exists, cfgate adopts it and records its UUID in `status.tunnelId`. If not, it creates a new tunnel.
- **Finalizers**: CRDs register finalizers (e.g. `cfgate.io/tunnel-finalizer`, `cfgate.io/dns-finalizer`). If `cfgate.io/deletion-policy: orphan` is set, controllers delete local state and remove finalizers without issuing Cloudflare API deletion calls.
- **DNS Ownership**: `CloudflareDNS` creates a TXT record alongside each managed CNAME using prefix `_cfgate.<subdomain>.<zone>` containing `heritage=cfgate,owner=<ownerId>,resource=<namespace>/<name>`. Records not matching the `ownerId` are ignored to prevent split-brain conflicts across multiple clusters.

#### Access Handling
- `CloudflareAccessPolicy` provisions reusable policies via Cloudflare Zero Trust API (`zero_trust.AccessPolicyNewParams`).
- `CloudflareAccessApplication` reconciles self-hosted Access Applications per route hostname/path. Reusable policies are linked by policy UUID.
- `status.observedApplications[].aud` exposes the application AUD tag on the Kubernetes CR.
- **Gap**: cfgate does *not* automatically propagate the AUD tag into cloudflared's `originRequest.access.aud` for in-tunnel cryptographic JWT validation. Cloudflare edge enforcement is trusted.
- Service tokens specified in `CloudflareAccessPolicy.spec.serviceTokens` generate Cloudflare Access Service Tokens and write `CF-Access-Client-Id` and `CF-Access-Client-Secret` directly into target Kubernetes Secrets.

#### Data Plane
- **Native cloudflared only**; no Envoy or in-pod L7 proxy.
- Deploys `cloudflared` using token authentication (`TUNNEL_TOKEN`). Uses the `ghcr.io/inherent-design/cloudflared:2026.5.0-h2c.1` fork to support cleartext HTTP/2 (`h2c`).
- Directly translates HTTPRoute rules to cloudflared ingress rules: `service: http://<service>.<ns>.svc.cluster.local:<port>`.
- Path matching converts `PathPrefix`, `Exact`, and `RegularExpression` into cloudflared regex patterns (`^/path(?:/.*)?$`, `^/path$`, etc.).
- **Restrictions**: Multi-backend routing (traffic splitting/weights) throws an error (`multiple backendRefs not supported`). Filters (`RequestHeaderModifier`, `URLRewrite`, `RequestRedirect`, `RequestMirror`) are silently ignored. Header, query, and HTTP method matching are completely unsupported.

#### Gaps & Roadmap History
- **PR #4 (Roadmap v0.2.0) & Issues #5, #12, #13, #16**: Proposed L4 routing (TCPRoute, UDPRoute), GRPCRoute, and WARP private network integration.
- **Status (Stopped on 2026-04-12)**: Formally closed and cancelled. Author confirmed: *"0.2.0 plan stopped here. Public TCP/UDP first does not fit current free-tier Cloudflare Tunnel model. Public TCP is client-side cloudflared. Public UDP is Spectrum, not Tunnel. Public-hostname gRPC is also out. Closing this roadmap PR. We are pivoting to core quality, testing, and stress work on the features cfgate already ships."*
- **PR #65**: Decomposed inline Access policies into reusable `CloudflareAccessPolicy` and target-bound `CloudflareAccessApplication`.
- **PR #72**: Introduced `CloudflareOriginPolicy` to formalize backend transport options with clear hierarchy.

#### License
- **Apache License 2.0**

---

### 2. StringKe/cloudflare-operator (`StringKe/cloudflare-operator`)

Originally forked from `adyanth/cloudflare-operator`, this project was rewritten into a comprehensive enterprise-grade Cloudflare operator supporting over 30 Custom Resources, native Ingress, and Gateway API.

#### CRD Inventory (`networking.cloudflare-operator.io/v1alpha2`)

| CRD Kind | Scope | Key Spec Fields | Attachment / Binding Mechanism |
|---|---|---|---|
| `Tunnel` | Namespaced | `name`, `cloudflare`, `originRequest`, `fallbackTarget` | Managed cloudflared deployment |
| `ClusterTunnel` | Cluster | `name`, `cloudflare`, `originRequest`, `fallbackTarget` | Cluster-wide cloudflared deployment |
| `TunnelGatewayClassConfig` | Cluster | `tunnelRef` (`kind`, `name`, `namespace`), `defaultOriginRequest`, `dnsManagement` (`Automatic`, `Manual`, `DNSRecord`), `dnsProxied`, `watchNamespaces[]` | Referenced by `GatewayClass.spec.parametersRef` |
| `TunnelIngressClassConfig` | Cluster | `tunnelRef`, `defaultOriginRequest`, `dnsManagement`, `dnsProxied` | Referenced by `IngressClass.spec.parametersRef` |
| `TunnelBinding` (v1alpha1) | Namespaced | `subjects[]` (`kind: Service`, `name`, `spec.fqdn`, `spec.protocol`, `spec.path`), `tunnelRef` | Binds raw Services to Tunnel |
| `AccessApplication` | Namespaced | `domain`, `selfHostedDomains[]`, `destinations[]`, `type`, `sessionDuration`, `identityProviderRefs[]`, `reusablePolicyRefs[]`, `reusableGroupRefs[]` | Standalone resource specifying domain/path |
| `AccessPolicy` | Cluster | `name`, `decision`, `precedence`, `include[]`, `exclude[]`, `require[]`, `sessionDuration` | Attached by `AccessApplication.spec.reusablePolicyRefs` |
| `AccessGroup` | Cluster | `name`, `include[]`, `exclude[]`, `require[]` | Referenced in AccessPolicy or AccessApplication |
| `AccessServiceToken` | Namespaced | `name`, `duration`, `secretRef` (`name`, `keyMapping`) | Provisions tokens and stores in Secret |
| `DNSRecord` | Namespaced | `zoneId` or `zoneName`, `type`, `name`, `content`, `ttl`, `proxied`, `comment`, `tags[]` | Standalone DNS management |
| `VirtualNetwork` | Cluster | `name`, `comment`, `isDefault` | Zero Trust private network isolation |
| `NetworkRoute` | Cluster | `network` (CIDR), `tunnelRef`, `virtualNetworkRef`, `comment` | Binds CIDR blocks to Tunnel for WARP routing |
| `WARPConnector` | Namespaced | `tunnelRef`, `devices` | Manages WARP client site-to-site connectivity |

#### Annotations Read by StringKe

| Annotation Key | Target Resource | Format / Options | Description |
|---|---|---|---|
| `cloudflare.com/protocol` | Ingress, Service, Route | `http`, `https`, `tcp`, `udp`, `ssh`, `rdp`, `smb`, `ws`, `wss` | Origin protocol override |
| `cloudflare.com/protocol-{port}` | Service | Protocol string | Port-specific protocol override |
| `cloudflare.com/no-tls-verify` | Ingress, Route | boolean string (`"true"`, `"false"`) | Disables origin TLS verification |
| `cloudflare.com/http2-origin` | Ingress, Route | boolean string | Enables HTTP/2 to backend |
| `cloudflare.com/ca-pool` | Ingress, Route | Secret name | Custom CA certificate secret |
| `cloudflare.com/connect-timeout` | Ingress, Route | Duration string (e.g. `"30s"`) | TCP connection timeout |
| `cloudflare.com/tls-timeout` | Ingress, Route | Duration string (e.g. `"10s"`) | TLS handshake timeout |
| `cloudflare.com/keep-alive-timeout` | Ingress, Route | Duration string (e.g. `"90s"`) | Keep-alive idle timeout |
| `cloudflare.com/keep-alive-connections`| Ingress, Route | Integer string (e.g. `"100"`) | Max idle connection pool size |
| `cloudflare.com/origin-server-name` | Ingress, Route | Hostname string | Origin SNI verification hostname |
| `cloudflare.com/http-host-header` | Ingress, Route | Hostname string | HTTP Host header override |
| `cloudflare.com/disable-dns` | Ingress, Route | boolean string (`"true"`) | Disables automatic DNS CNAME generation |
| `cloudflare.com/dns-proxied` | Ingress, Route | boolean string (`"true"`, `"false"`) | Controls Cloudflare proxy status |
| `cloudflare.com/disable-chunked-encoding`| Ingress, Route | boolean string | Disables chunked transfer encoding |
| `cloudflare.com/bastion-mode` | Ingress, Route | boolean string | Enables bastion mode |
| `cloudflare-operator.io/managed-by` | Cloudflare resources | `<namespace>/<name>` | Ownership marker for adoption checking |

#### Ownership and Adoption
- Implements `AdoptionChecker`: Inspects existing Cloudflare resources during reconciliation. If the resource is unmanaged or the metadata description/tag matches `cloudflare-operator.io/managed-by: <ns>/<name>`, it adopts the resource. If it is claimed by another controller or installation, it fails with `ErrResourceConflict`.
- Uses standard Kubernetes finalizers (`DeletionHandler`) to clean up Cloudflare API resources unless deleted with specific annotations.

#### Tunnel Single-Writer Architecture (ConfigMap Aggregation)
- `StringKe` implements a **Three-Layer / Single-Writer Architecture** to avoid race conditions against the Cloudflare Tunnel Configuration API:
  - Each Tunnel owns an internal `ConfigMap` labeled `cloudflare-operator.io/type: tunnel-config` and `cloudflare-operator.io/tunnel-id: <tunnelId>`.
  - Inside `ConfigMap.Data["config.json"]`, a map of `SourceConfig` objects is maintained (`HTTPRoute/<ns>/<name>`, `Ingress/<ns>/<name>`, `TunnelBinding/<ns>/<name>`).
  - When routes or ingresses update, they write only their local fragment into the Tunnel's ConfigMap.
  - A separate `TunnelConfig Controller` watches this ConfigMap, merges all rules with deterministic priorities (`PriorityTunnelSettings=10`, `PriorityBinding=50`, `PriorityIngress=100`, `PriorityGateway=100`), appends the fallback rule, hashes the configuration, and performs a single serialized update to Cloudflare's API via `UpdateTunnelConfiguration`.

#### Access Handling
- Completely independent CRD ecosystem for Access: `AccessApplication` does not require Gateway API; it defines domains directly.
- Supports reusable policies (`AccessPolicy`), group memberships (`AccessGroup`), and IdP configurations (`AccessIdentityProvider`).
- `AccessServiceToken` handles M2M token generation and writes credentials into Kubernetes Secrets.
- Does not inject AUD tokens into `cloudflared` local ingress rules.

#### Data Plane
- **Native cloudflared only** (no Envoy or in-cluster L7 reverse proxy).
- Gateway API routes are flattened into basic cloudflared ingress rules. Gateway filters, weighted backends, and HTTP method/query/header matchers are discarded during conversion.

#### License
- **Apache License 2.0**

---

### 3. lexfrei/cloudflare-tunnel-gateway-controller (`lexfrei/cloudflare-tunnel-gateway-controller`)

`lexfrei` is a purpose-built, Gateway API v1.6.1 conformant implementation for Cloudflare Tunnel that bridges Cloudflare edge routing with rich in-cluster L7 proxying.

#### CRD Inventory (`gateway.cloudflare.com/v1alpha1`)

| CRD Kind | Scope | Key Spec Fields | Attachment / Binding Mechanism |
|---|---|---|---|
| `GatewayClassConfig` | Cluster | `cloudflareCredentialsSecretRef` (`api-token`), `accountId` (validated by CEL 32-char hex pattern) | Referenced by `GatewayClass.spec.parametersRef` |
| `GatewayConfig` | Namespaced | `tunnelTokenSecretRef`, `cloudflareCredentialsSecretRef` (override), `authTokenSecretRef`, `replicas`, `autoscaling`, `resources`, `image` | Referenced by `Gateway.spec.infrastructure.parametersRef` |
| `ExternalBackend` | Namespaced | `scheme` (`http`/`https`), `host`, `port`, `path` | Referenced as a `backendRef` in `HTTPRoute` rules |

#### Annotations Read by lexfrei
- **Zero proprietary annotations on HTTPRoute or Service**.
- Fully adopts standard Gateway API specifications:
  - Uses `spec.listeners` on `Gateway` for protocol/port/hostname binding.
  - Uses `Gateway.status.addresses` to publish `{tunnelID}.cfargotunnel.com`.
  - Uses standard `BackendTLSPolicy` for backend TLS configuration.
  - Uses `appProtocol: kubernetes.io/ws` or `kubernetes.io/wss` on `Service` for WebSockets.
  - Evaluates standard `HTTPRoute` filters (`RequestHeaderModifier`, `ResponseHeaderModifier`, `URLRewrite`, `RequestRedirect`, `RequestMirror`).

#### Ownership and Multi-Tenancy Models
- **Tunnel Ownership Arbitration (`internal/tunnelownership`)**: A tunnel belongs strictly to the Gateway already serving it; the class tunnel belongs to the operator. If another Gateway in a different namespace attempts to claim the same tunnel UUID, it is rejected outright to prevent cross-tenant traffic hijacking.
- **Hostname Ownership Enforcement (`internal/hostnameownership`)**: Defense-in-depth enforcement:
  1. CEL `ValidatingAdmissionPolicy` checks at admission time whether an HTTPRoute/GRPCRoute hostname matches allowed namespace suffix labels.
  2. Controller-side evaluation rejects any route violating the hostname label policy before it is programmed into the proxy data plane.

#### Access Handling
- **None**: Does not manage Cloudflare Access Applications, policies, or service tokens. Focuses strictly on L7 data plane routing and tunnel transport.

#### Data Plane Architecture: Embedded In-Process L7 Reverse Proxy
- **Unique Architecture**: Instead of running stock `cloudflared`, `lexfrei` deploys an in-process Go L7 reverse proxy inside the `cloudflared` container utilizing cloudflared's internal `OverrideProxy` hook (via `github.com/lexfrei/cloudflared`).
- **Mechanism**:
  - The controller programs Cloudflare Tunnel's remote config with a single catch-all ingress rule directing all traffic to the embedded local proxy.
  - The controller pushes the complete Gateway API route model dynamically to the local proxy via an authenticated HTTP configuration push API (`hot reload`, zero pod restarts).
  - The embedded reverse proxy evaluates full Gateway API L7 semantics: path prefix/exact/regex matching, header matching, query parameter matching, HTTP method matching, URL rewriting, header modification, redirects, request mirroring, and weighted traffic splits across backends.
  - Cross-namespace backend references are fully validated via `ReferenceGrant`.

#### DNS Handling
- The controller does **not** create Cloudflare DNS records directly.
- It writes the tunnel domain (`<tunnelID>.cfargotunnel.com`) into `Gateway.status.addresses` with type `NamedAddress` / `Hostname`.
- DNS record provisioning is delegated to `external-dns`, which watches the Gateway and creates CNAME records automatically.

#### License
- **BSD 3-Clause License**

---

### 4. adyanth/cloudflare-operator (`adyanth/cloudflare-operator`)

The original community operator that pioneered managing Cloudflare Tunnels on Kubernetes via Custom Resources.

#### CRD Inventory (`networking.cfargotunnel.com/v1alpha1`)

| CRD Kind | Scope | Key Spec Fields | Attachment / Binding Mechanism |
|---|---|---|---|
| `Tunnel` | Namespaced | `name`, `cloudflare.secretRef`, `cloudflare.accountId`, `size` (replicas) | Direct tunnel deployment |
| `ClusterTunnel` | Cluster | `name`, `cloudflare.secretRef`, `cloudflare.accountId`, `size` | Cluster-wide tunnel deployment |
| `TunnelBinding` | Namespaced | `subjects[]` (`kind: Service`, `name`, `spec.fqdn`, `spec.protocol`, `spec.target`, `spec.caPool`, `spec.noTlsVerify`), `tunnelRef.name`, `tunnelRef.kind`, `tunnelRef.disableDNSUpdates` | References Service name in `subjects` and Tunnel in `tunnelRef` |
| `AccessTunnel` | Namespaced | `target.fqdn`, `target.protocol`, `target.svc.port`, `serviceToken` | Client-side cluster proxy for arbitrary TCP Access |

#### Annotations Read
- Replaced legacy Service annotations with the `TunnelBinding` CRD.

#### Ownership & Data Plane
- **Data Plane**: Native stock `cloudflared`.
- **Config Sync**: Pure ConfigMap-based with Pod restarts. When a `TunnelBinding` is created or modified, the controller updates the `cloudflared` `ConfigMap` and issues an explicit rolling restart of the `cloudflared` Deployment.
- **DNS**: Creates proxied CNAME records in Cloudflare DNS pointing `fqdn` to `<tunnelID>.cfargotunnel.com`.

#### License
- **Apache License 2.0**

---

### 5. kubernetes-sigs/external-dns (Cloudflare Provider & Gateway API Source)

`external-dns` synchronizes exposed Kubernetes services, Ingresses, and Gateway API routes with external DNS providers, including Cloudflare.

#### Exact Cloudflare Provider Annotations
Verified directly against `kubernetes-sigs/external-dns` source (`source/annotations/annotations.go` and `provider/cloudflare/cloudflare.go`):

| Annotation Key | Value Format / Type | Purpose |
|---|---|---|
| `external-dns.alpha.kubernetes.io/cloudflare-proxied` | boolean string (`"true"`, `"false"`) | Toggles Cloudflare CDN/WAF/DDoS proxy (orange cloud vs grey cloud) |
| `external-dns.alpha.kubernetes.io/cloudflare-custom-hostname` | comma-separated string | Sets custom hostnames for Cloudflare for SaaS (SSL for SaaS) |
| `external-dns.alpha.kubernetes.io/cloudflare-region-key` | string (e.g. `"eu"`, `"us"`) | Configures Regional Services data localization |
| `external-dns.alpha.kubernetes.io/cloudflare-record-comment` | string | Injects a human-readable comment into the Cloudflare DNS record |
| `external-dns.alpha.kubernetes.io/cloudflare-tags` | comma-separated string | Attaches Cloudflare DNS tags for search and organization |

*(Note: The tag annotation is `cloudflare-tags`, not `cloudflare-record-tags`).*

#### Gateway API Source Resolution Model (`source/gateway.go`)
1. **Route Extraction**: Watches `HTTPRoute`, `GRPCRoute`, `TCPRoute`, `TLSRoute`, `UDPRoute`.
2. **Listener Intersection**: Reconciles the route's `spec.hostnames` against the parent `Gateway.spec.listeners[].hostname`. Only hostnames intersecting an attached listener are processed.
3. **Target Resolution**: Reads target endpoints from `Gateway.status.addresses`:
   - If `Gateway.status.addresses` contains `type: Hostname` with value `<tunnelID>.cfargotunnel.com`, external-dns generates a CNAME record: `app.example.com CNAME <tunnelID>.cfargotunnel.com`.
   - If `Gateway.status.addresses` contains IP addresses, it generates `A`/`AAAA` records.
4. **Provider-Specific Metadata**: Extracts `external-dns.alpha.kubernetes.io/*` annotations from the Route resource and passes them to the Cloudflare provider (e.g., setting `proxied: true`).

#### TXT Registry Ownership Model (`registry/txt/registry.go`)
- **Format**: Generates associated TXT records formatted as:
  `"heritage=external-dns,external-dns/owner=<ownerID>,external-dns/resource=<namespace>/<kind>/<name>"`
- **CNAME Collision Prevention**: In standard DNS (RFC 1034/1035), a CNAME record cannot coexist with any other record type at the same node. To track ownership of CNAME records without violating DNS specs, external-dns mandates a naming mapper:
  - `--txt-prefix`: prepends a prefix (e.g. `_external-dns.app.example.com`).
  - `--txt-suffix`: appends a suffix (e.g. `app.example.com._external-dns`).
- Records without the matching `ownerID` in their TXT counterpart are treated as unowned and left untouched.

#### License
- **Apache License 2.0**

---

### 6. Other Cloudflare Operators

#### STRRL/cloudflare-tunnel-ingress-controller
- **Modeling Pattern**: Pure Kubernetes `Ingress` controller (`networking.k8s.io/v1`). Introduces **no custom CRDs**.
- **Mechanism**: Watches `Ingress` resources with `ingressClassName: cloudflare-tunnel`. Deploys an in-cluster `cloudflared` pod configured via Remote Config API.
- **Annotations**: Extensively uses annotations under `cloudflare-tunnel-ingress-controller.strrl.dev/`:
  - Transport & TLS: `backend-protocol`, `proxy-ssl-verify`, `no-tls-verify`, `origin-server-name`, `http-host-header`, `http2-origin`.
  - Origin Parameters: `connect-timeout`, `tls-timeout`, `tcp-keepalive`, `no-happy-eyeballs`, `keepalive-connections`, `keepalive-timeout`, `disable-chunked-encoding`.
  - DNS: `disable-dns-management` (allows delegating DNS entirely to external-dns).
- **License**: Apache 2.0.

#### cloudflare/cloudflare-ingress-controller (Legacy)
- **Modeling Pattern**: Official, legacy Ingress controller from Cloudflare.
- **Mechanism**: Monitored Ingress resources and invoked the older Argo Tunnel CLI/API to dynamically bind tunnels to services. Required a Cloudflare certificate pem file (`cert.pem`) mounted into the pod.
- **Status**: Deprecated by Cloudflare; does not support modern Named Tunnels, Gateway API, or Cloudflare Zero Trust Access policies.
- **License**: Apache 2.0.

#### AccessTunnel / Client-Side WARP Connectors
- Modeled in `adyanth` (`AccessTunnel`) and `StringKe` (`WARPConnector` / `PrivateService`).
- Used to deploy client-side `cloudflared access` daemons inside the cluster to dial remote TCP/UDP endpoints over Cloudflare Tunnels without requiring host-level WARP client installation.

---

## Cross-Project Comparison

| Feature / Dimension | cfgate (`cfgate`) | StringKe Operator | lexfrei Gateway Controller | adyanth Operator | STRRL Ingress Controller | external-dns (CF Provider) |
|---|---|---|---|---|---|---|
| **Primary API Surface** | Gateway API (`HTTPRoute`, `Gateway`) | Ingress, Gateway API, Service | Gateway API (`HTTPRoute`, `GRPCRoute`) | Service (`TunnelBinding`) | Ingress (`networking.k8s.io`) | Ingress & Gateway API |
| **CRD Count** | 5 (Tunnel, DNS, AccessApp, AccessPolicy, OriginPolicy) | 30+ (Tunnel, DNS, Access, Rules, R2, Pages, VNet) | 3 (GatewayClassConfig, GatewayConfig, ExternalBackend) | 4 (Tunnel, ClusterTunnel, TunnelBinding, AccessTunnel) | 0 (Pure Ingress) | 0 (Core external-dns) |
| **Attachment Mechanism** | Annotation on Gateway + GEP-713 `targetRef` on Access/Origin CRDs | `parametersRef` on GatewayClass/IngressClass; TunnelBinding | `parametersRef` on GatewayClass and Gateway infrastructure | `subjects` list in `TunnelBinding` | `ingressClassName` + Annotations | Watches native Gateway & Route objects |
| **Data Plane** | Native `cloudflared` (h2c fork) | Native `cloudflared` | **Embedded L7 Proxy** inside `cloudflared` (`OverrideProxy`) | Native `cloudflared` | Native `cloudflared` | N/A (Control plane only) |
| **Gateway API Conformance** | Minimal (path regex only; no filters, no weights) | Minimal (path regex only; no filters, no weights) | **v1.6.1 Conformant** (headers, query, method, filters, splits) | None | None | Conforms to Gateway API source reading |
| **Tunnel Config Writer** | Monolithic route collection on reconcile | **ConfigMap Buffer + Dedicated Single-Writer Controller** | Single-writer per Gateway / Tunnel arbitration | Direct ConfigMap rewrite + Deployment restart | Direct Remote Config API update | N/A |
| **Access Zero Trust** | Decoupled: Reusable Policies + App TargetRef bindings | Direct: Full CRD suite (`AccessApplication`, `AccessPolicy`) | None | Arbitrary TCP `AccessTunnel` only | None | None |
| **AUD Verification in Tunnel** | Status exposure only; no `originRequest.access` injection | None | None | Manual Service Token secret | None | N/A |
| **DNS Management** | Dedicated `CloudflareDNS` CRD (multi-zone, TXT ownership) | Tri-mode: Automatic, Manual, or `DNSRecord` CRDs | **Delegated to external-dns** via `Gateway.status.addresses` | Direct CNAME creation in controller | Direct CNAME creation in controller (opt-out) | Provider-level sync + TXT registry |
| **License** | Apache 2.0 | Apache 2.0 | BSD 3-Clause | Apache 2.0 | Apache 2.0 | Apache 2.0 |

---

## Modeling Patterns Observed

### Pattern 1: Annotation-Heavy on Native Routes / Services (STRRL, early adyanth)
- **Mechanism**: Ingress or Service resources are annotated with `cloudflare.com/*` or vendor prefixes specifying origin protocols, timeouts, TLS verification, and DNS settings.
- **Pros**: Zero additional CRDs; works with existing GitOps manifests.
- **Cons**: Severe annotation sprawl; untyped validation (errors caught only at runtime); impossible to model complex zero-trust structures (e.g. multi-condition Access policies with include/exclude/require); breaks portability of Gateway API routes.

### Pattern 2: GEP-713 Policy Attachment with `targetRef` (`cfgate`)
- **Mechanism**: Dedicated namespaced CRDs (`CloudflareAccessApplication`, `CloudflareOriginPolicy`) target `HTTPRoute` or `Gateway` via `spec.targetRef` (Group, Kind, Name, SectionName).
- **Pros**:
  - Aligns with standard Kubernetes Gateway API policy attachment guidelines (GEP-713).
  - Keeps HTTPRoutes portable across different Gateway controllers (e.g. Envoy Gateway, Cilium).
  - Permits fine-grained RBAC (developers manage routes in app namespaces; security teams manage Access policies in system namespaces).
  - Cross-namespace safety can be gated with `ReferenceGrant`.
- **Cons**: Controller must implement bidirectional indexers and complex watch mapping between policies and target routes; status reporting requires strict condition handling (`Accepted`, `TargetNotFound`).

### Pattern 3: Gateway `parametersRef` for Infrastructure Binding (`lexfrei`, `StringKe`)
- **Mechanism**: Uses Gateway API's native configuration extension points:
  - `GatewayClass.spec.parametersRef` -> points to cluster-scoped controller configuration (`GatewayClassConfig`).
  - `Gateway.spec.infrastructure.parametersRef` (Gateway API v1.1+) -> points to namespaced tunnel binding configuration (`GatewayConfig` / `TunnelGatewayClassConfig`).
- **Pros**:
  - Eliminates custom annotations like `cfgate.io/tunnel-ref` on Gateways.
  - Standardized in Gateway API v1.1+; supported by client-go and controller-runtime scaffolding.
  - Allows each Gateway to declare its own tunnel credentials, replica counts, or autoscaling parameters cleanly.
- **Cons**: Requires Gateway API standard CRDs v1.1+; users must maintain separate config resources.

### Pattern 4: Intermediate Buffer for Tunnel Single-Writer API (`StringKe`)
- **Mechanism**: Rather than having every route controller directly call Cloudflare's `UpdateTunnelConfiguration` API (which overwrites the entire ingress rule array), controllers write their rule fragments into a shared Kubernetes `ConfigMap` owned by the Tunnel. A single `TunnelConfig Controller` watches the ConfigMap, aggregates rules by priority, and writes to Cloudflare.
- **Pros**:
  - Eliminates Cloudflare API rate-limiting and race conditions when multiple routes update concurrently.
  - Transparent debugging (inspect `kubectl get cm <tunnel-id> -o json` to see all active sources and rules).
  - Provides clear rule priority order (`TunnelSettings` > `Binding` > `Ingress` / `Gateway`).
- **Cons**: Extra Kubernetes API churn; potential ConfigMap size limits (1MB, though enough for thousands of ingress rules).

### Pattern 5: Embedded In-Process L7 Reverse Proxy (`lexfrei`)
- **Mechanism**: Replaces stock `cloudflared` with an in-process proxy binary that hooks `cloudflared`'s transport via `OverrideProxy`. Cloudflare Tunnel serves as a simple L4/L7 transport pipe; all Gateway API matching, filters, and weighted load balancing are executed in-cluster.
- **Pros**:
  - **Full Gateway API Conformance**: Unlocks headers, queries, methods, rewrites, redirects, mirroring, and weighted splits that Cloudflare Tunnel natively cannot do.
  - **Hot Reload**: Routing updates apply instantly in-memory without waiting for Cloudflare API propagation or restarting pods.
- **Cons**:
  - Requires maintaining a custom fork of `cloudflared`.
  - In-pod proxy consumes additional memory and CPU.
  - Traffic enters the cluster before advanced path-level Access policy enforcement (unless Access is evaluated at the edge).

### Pattern 6: Delegating DNS to `external-dns` via `status.addresses` (`lexfrei`)
- **Mechanism**: The tunnel operator does not manage DNS records at all. It publishes `{tunnelID}.cfargotunnel.com` to `Gateway.status.addresses`. `external-dns` watches the Gateway and creates CNAME records.
- **Pros**:
  - Clean separation of concerns (tunnel controller manages tunnels; DNS operator manages DNS).
  - Leverages robust external-dns features (multi-provider, TXT registry ownership, advanced filtering).
- **Cons**: Requires installing and configuring `external-dns`; two controllers must reconcile before traffic flows.

---

## Sources

- **cfgate**:
  - Repository: `https://github.com/cfgate/cfgate`
  - Docs: `docs/cloudflare-access-application.md`, `docs/cloudflare-access-policy.md`, `docs/cloudflare-tunnel.md`, `docs/cloudflare-dns.md`, `docs/annotations.md`
  - PRs & Issues: PR #4 (`docs: v0.2.0 planning roadmap and protocol analysis`), PR #65 (`Split Access policies from applications`), PR #72 (`feat: add origin policy API contracts`), Issues #5, #12, #13, #16
- **StringKe/cloudflare-operator**:
  - Repository: `https://github.com/StringKe/cloudflare-operator`
  - API Types: `api/v1alpha2/tunnelgatewayclassconfig_types.go`, `accessapplication_types.go`, `accesspolicy_types.go`, `accessservicetoken_types.go`
  - Controllers: `internal/controller/gateway/gateway_controller.go`, `internal/controller/tunnelconfig/controller.go`, `internal/controller/adoption.go`
- **lexfrei/cloudflare-tunnel-gateway-controller**:
  - Repository: `https://github.com/lexfrei/cloudflare-tunnel-gateway-controller`
  - Docs & Code: `README.md`, `api/v1alpha1/gatewayconfig_types.go`, `gatewayclassconfig_types.go`, `internal/tunnelownership/ownership.go`, `internal/hostnameownership/policy.go`
- **adyanth/cloudflare-operator**:
  - Repository: `https://github.com/adyanth/cloudflare-operator`
  - Docs & Code: `README.md`, `api/v1alpha1/tunnelbinding_types.go`, `docs/configuration/tunnel-binding.md`, `docs/configuration/access-tunnel.md`
- **kubernetes-sigs/external-dns**:
  - Repository: `https://github.com/kubernetes-sigs/external-dns`
  - Source: `provider/cloudflare/cloudflare.go`, `source/annotations/annotations.go`, `source/gateway.go`, `source/gateway_httproute.go`, `registry/txt/registry.go`, `endpoint/labels.go`
- **STRRL/cloudflare-tunnel-ingress-controller**:
  - Repository: `https://github.com/STRRL/cloudflare-tunnel-ingress-controller`
  - Source: `pkg/controller/well_known_annotations.go`

---

## Open Questions / Gaps

1. **Cloudflare Tunnel Local JWT Validation (`originRequest.access`)**:
   - `cloudflared` supports local JWT validation using `originRequest.access.audTag` (or `originRequest.access.teamName`), which verifies Cloudflare Access JWTs locally at the tunnel connector before forwarding requests to the origin.
   - None of the reviewed operators (`cfgate`, `StringKe`, `lexfrei`) automatically link the generated Access Application AUD tag into cloudflared's ingress rule `originRequest.access`. Investigating whether Flareway should automate this end-to-end cryptographic bridge is a prime design opportunity.
2. **In-Pod L7 Proxy vs Native cloudflared**:
   - Is Flareway's primary objective 100% Gateway API conformance (which strictly requires an in-pod proxy like Envoy or lexfrei's Go proxy to handle filters, headers, queries, and weights), or is a native cloudflared-only integration (like cfgate) acceptable if documented as non-conformant?
3. **WARP / L4 Feasibility on Free vs Enterprise Tiers**:
   - As confirmed by cfgate's canceled roadmap, public TCP/UDP over Cloudflare Tunnel either requires client-side `cloudflared` proxies or Cloudflare Spectrum ($$$). For private WARP routing (CIDRs via `VirtualNetwork`), does Flareway intend to manage client WARP profiles / device settings, or strictly cluster-side tunnel routes?
4. **Multi-Writer Tunnel Synchronization**:
   - If Flareway supports multiple Gateways sharing one Cloudflare Tunnel, should it adopt `StringKe`'s Kubernetes `ConfigMap` aggregation buffer pattern, or restrict each Gateway to a dedicated Cloudflare Tunnel?
