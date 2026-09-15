# SaaS Edge Analogs for Gateway API & Outbound Connector Operators

## Summary (10 bullets max)
- **External SaaS Edge vs. Gateway API Conformance Tension**: Pure outbound edge tunnels (cloudflared native ingress rules) match only Hostname and Path prefix/regex. They physically cannot evaluate HTTP methods, arbitrary header matches, query parameter matches, or Gateway API standard filters (`RequestRedirect`, `RequestHeaderModifier`, `URLRewrite`).
- **Data Plane Dual Strategy**: To achieve Gateway API conformance without edge rewrites, operators deploy an in-cluster L7 proxy (Envoy or custom Go proxy) behind the tunnel (proven by Lexfrei’s Conformant v1.6.1 implementation and STRRL’s ADR 0002), or translate HTTPRoute rules into sophisticated edge DSL rules (proven by ngrok's edge Traffic Policy engine).
- **Public Edge TLS Ownership**: All edge SaaS implementations (ngrok, Cloudflare, Azure AGC, Tailscale Funnel) terminate TLS at the vendor edge. `Gateway.spec.listeners[].tls.certificateRefs` are either ignored (edge uses managed certs), uploaded out-of-band to edge SaaS APIs (ngrok custom domain certs), or rejected (Passthrough mode is rejected).
- **Address & DNS Realities (`status.addresses`)**: Edge SaaS providers do not allocate arbitrary cluster IP addresses to Gateways. They populate `Gateway.status.addresses` with `HostnameAddressType`, providing the canonical edge CNAME target (e.g., `*.ngrok-cname.com`, `<tunnel-id>.cfargotunnel.com`) or the managed FQDN.
- **ngrok Gateway API & TrafficPolicy**: ngrok supports Gateway API v1 via GatewayClass `ngrok` (`spec.controllerName: ngrok.com/gateway-controller`). Gateway-level policies use the `ngrok.com/traffic-policy` annotation, whereas per-route policies strictly use Gateway API native `filters[].type: ExtensionRef` pointing to `ngrok.com/v1 TrafficPolicy`.
- **Identity / Auth Modeling (Attachment vs. External Reference)**: Two primary paradigms exist: (1) In-cluster policy attachment CRDs (`TrafficPolicy` via `ExtensionRef` in ngrok, GEP-713 `CloudflareAccess` CRD in STRRL, `RoutePolicy` in Azure AGC); and (2) External decoupled policy referenced by tag (Tailscale’s `tailscale.com/tags` where ACLs and grants live entirely outside K8s in Tailscale's HuJSON policy file).
- **Tailscale Gateway API Non-Support**: The Tailscale Kubernetes operator supports Ingress (IngressClass `tailscale`) and Service (`tailscale.com/expose: "true"`), but as of September 2026 has **zero** Gateway API (`gateway.networking.k8s.io`) support.
- **Official Cloudflare Controller Absence**: Cloudflare does not maintain or publish an official Gateway API controller or modern Kubernetes Tunnel operator (the 2018 `cloudflare/cloudflare-ingress-controller` was archived years ago). All existing implementations (`STRRL`, `adyanth`, `lexfrei`, `pl4nty`) are community-developed.
- **Conformance Test Reachability Gap**: Standard Gateway API conformance suites send synthetic HTTP requests with arbitrary hostnames (e.g., `example.com`, `foo.org`). Cloudflare and SaaS edge networks drop traffic for hostnames not registered in the account's DNS zone, forcing test suites to either skip foreign-host tests or run a local cluster-internal test loop.
- **Whole-Object vs. Multi-Route Reconciliation**: Cloudflare Tunnel ingress configurations and ngrok endpoint pools operate on whole-object lists. Controllers resolve this by maintaining an internal In-Memory Representation (IR) cache / Driver pattern that materializes the unified state across all Gateways, Routes, and Services before flushing updates.

---

## ngrok operator

The ngrok Kubernetes Operator enables Kubernetes clusters to publish services to the internet via the ngrok SaaS edge network through outbound TLS connections established by in-cluster agents.

### CRD Table

All ngrok operator CRDs belong to the `ngrok.com` or `*.ngrok.com` groups. Under the active v1 migration, resources are consolidating under `ngrok.com/v1`.

| Group / Version | Kind | Scope | Key Spec Fields | Description |
|---|---|---|---|---|
| `ngrok.com/v1` | `TrafficPolicy` | Namespaced | `policy` (schemaless `json.RawMessage`, containing `on_http_request`, `on_http_response`, `on_tcp_connect` phase rules) | Replaces deprecated `NgrokTrafficPolicy`. Defines actions for auth (OAuth, OIDC, JWT), traffic shaping, headers, rate limiting, and internal routing. |
| `ngrok.k8s.ngrok.com/v1alpha1` | `NgrokTrafficPolicy` | Namespaced | `policy` (raw JSON) | Deprecated legacy name for `TrafficPolicy`. Maintained via passive dual-read shims in the operator store. |
| `ngrok.k8s.ngrok.com/v1alpha1` | `AgentEndpoint` | Namespaced | `url`, `upstream.url`, `trafficPolicy.targetRef`, `trafficPolicy.inline`, `bindings`, `clientCertificateRefs` | Represents a live tunnel endpoint terminating inside the Kubernetes cluster on an ngrok agent pod. |
| `ngrok.k8s.ngrok.com/v1alpha1` | `CloudEndpoint` | Namespaced | `url`, `trafficPolicy.targetRef`, `trafficPolicy.inline`, `bindings`, `poolingEnabled` | Cloud-hosted edge endpoint on ngrok's edge. Typically forwards to an internal `AgentEndpoint` via `forward-internal` action. |
| `ngrok.k8s.ngrok.com/v1alpha1` | `KubernetesOperator` | Namespaced | `enabledFeatures` (`ingress`, `gateway`, `bindings`), `region`, `binding` | Controls operator-level behavior, feature gates, and multi-tenant agent bindings. |
| `ingress.k8s.ngrok.com/v1alpha1` | `Domain` | Namespaced | `domain`, `reclaimPolicy` (`Delete`, `Retain`), `metadata` | Manages reservation and lifecycle of an ngrok domain and tracks edge CNAME target status. |
| `ingress.k8s.ngrok.com/v1alpha1` | `IPPolicy` | Namespaced | `rules` (`action`, `cidr`, `description`) | Edge IP allowlist/denylist policy resource. |
| `bindings.k8s.ngrok.com/v1alpha1` | `BoundEndpoint` | Namespaced | `endpointURL`, `target.service`, `target.port`, `scheme` | Connects internal cluster workloads to virtual endpoints across clusters. |

### Annotation Table

The ngrok operator migrated canonical annotations from `k8s.ngrok.com/*` to `ngrok.com/*`. Both are accepted during reconciliation; `ngrok.com/*` takes precedence.

| Annotation Key | Target Kind | Purpose |
|---|---|---|
| `ngrok.com/traffic-policy` | `Gateway`, `Ingress`, `Service` | Attaches a `TrafficPolicy` resource by name in the same namespace to the endpoint(s) created for that resource. |
| `ngrok.com/mapping-strategy` | `Gateway`, `Ingress`, `Service` | Values: `endpoints` (default: creates single public `AgentEndpoint`) or `endpoints-verbose` (creates edge `CloudEndpoint` + internal `.internal` `AgentEndpoint`). |
| `ngrok.com/pooling-enabled` | `Gateway`, `Ingress`, `Service` | Boolean (`"true"`/`"false"`). Enables multi-cluster traffic pooling/balancing to the same hostname. |
| `ngrok.com/bindings` | `Gateway`, `Ingress`, `Service` | Controls network visibility: `public`, `internal`, or `kubernetes`. |
| `ngrok.com/url` | `Service` (LoadBalancer) | Explicit public URL (e.g. `tcp://1.tcp.ngrok.io:12345` or `tls://example.com`). |
| `ngrok.com/app-protocols` | Backend `Service` | JSON map (`{"port-name": "HTTPS"}`) specifying upstream proxy protocol (`HTTP`, `HTTPS`, `TCP`, `TLS`). |
| `ngrok.com/description` | `Gateway`, `Ingress` | Human-readable description passed to ngrok edge endpoint metadata. |
| `ngrok.com/metadata` | `Gateway`, `Ingress` | JSON string of arbitrary metadata tags attached to the ngrok cloud endpoint. |
| `ngrok.com/computed-url` | `Service` (LoadBalancer) | Operator-written internal status annotation recording the external URL. |

### Gateway API Mapping Architecture

- **GatewayClass**: Registers `spec.controllerName: ngrok.com/gateway-controller`. The operator validates this string and marks the GatewayClass status `Accepted: True`.
- **Gateway**: A Gateway resource defines one or more listeners. If `Gateway.spec.addresses` is omitted, each listener MUST define a valid, non-empty, fully-qualified domain name in `listener.hostname` (wildcards without a root domain like `*` are rejected).
- **Endpoint Materialization**:
  - In `endpoints-verbose` mode:
    - Creates a `CloudEndpoint` at `https://<listener.hostname>`.
    - Synthesizes an inline traffic policy on the `CloudEndpoint` with rules matching HTTPRoute paths (`req.url.path.startsWith('/...')`) whose action is `forward-internal` pointing to a private `.internal` domain (e.g., `https://<hash>-<svc>-<ns>-<port>.internal`).
    - Creates an in-cluster `AgentEndpoint` bound to that `.internal` domain forwarding traffic to the backend Kubernetes `ClusterIP:Port`.
  - In default `endpoints` mode:
    - Collapses to a single in-cluster `AgentEndpoint` bound directly to the public domain with inline traffic policy rules that filter requests and issue `404` for unmatched paths.
- **TCPRoute / TLSRoute**: Because Gateway API v1 forbids hostnames on TCP listeners, ngrok requires users to supply the domain/TCP address in `Gateway.spec.addresses` when using TCPRoute or TLSRoute.
- **Edge TLS Termination**: For HTTPS listeners, ngrok edge terminates TLS using ngrok's edge-managed certificates by default. If `listener.tls.certificateRefs` is specified, the operator resolves the referenced Kubernetes `kubernetes.io/tls` Secret and uploads/provisions the custom certificate to the ngrok edge. Listener TLS options under `ngrok.com/terminate-tls.<option>` configure edge cipher suites and TLS min/max versions.
- **Status.Addresses**: `Gateway.status.addresses` is populated with entries of type `HostnameAddressType`. If the domain is a custom domain backed by an ngrok `Domain` resource with a CNAME target, `status.addresses[].value` is populated with the CNAME target (e.g. `*.ngrok-cname.com`). For ngrok-managed domains, it is populated with the normalized FQDN.
- **Supported / Unsupported Features & Signaling**:
  - Supported HTTPRoute matches: Path (Prefix, Exact, Regex), Headers (Exact, Regex), Query Params (Exact, Regex), HTTP Methods.
  - Supported HTTPRoute filters: `RequestHeaderModifier`, `ResponseHeaderModifier`, `RequestRedirect`, `URLRewrite`, and `ExtensionRef`.
  - Unsupported filter: `RequestMirror` is explicitly rejected.
  - Unsupported feature signaling: When an unsupported filter is encountered, the translator logs `skipping filter with error` and does not attach the filter. The route itself remains `Accepted: True` if parentRefs are valid.

### Decision Rationale: Annotations vs. ExtensionRef

ngrok's architectural documentation (`specs/features/gateway-api.md` and `specs/features/traffic-policy.md`) articulates a clear boundary:
1. **Coarse (Gateway-Level) Configuration via Annotations**: Annotations (`ngrok.com/traffic-policy`, `ngrok.com/mapping-strategy`, `ngrok.com/pooling-enabled`) are supported **only on Gateway resources**. Per-route annotation overrides on HTTPRoute / TCPRoute / TLSRoute are deliberately not supported.
2. **Fine-Grained (Route-Level) Configuration via ExtensionRef**: For rule- and route-level behavior, ngrok aligns strictly with the Kubernetes Gateway API specification. Route rules execute custom actions via `filters[].type: ExtensionRef` pointing to an `ExtensionRef` of `kind: TrafficPolicy` (group `ngrok.com`).
3. **Safety & Scope**: Traffic policies applied via `ExtensionRef` inside an HTTPRoute rule are validated to ensure they do not contain `on_tcp_connect` phase rules (which can only execute at initial connection time and cannot be scoped to an HTTP path).

### Auth & Identity Modeling

ngrok models identity-aware access as first-class actions within its `TrafficPolicy` engine:
- `oauth`: Built-in managed OAuth providers (Google, GitHub, Microsoft, etc.) with cookie sessions, scopes, and email domain restrictions.
- `openid-connect`: Generic OIDC against any IdP with `issuer_url`, client credentials, and userinfo refresh.
- `jwt-validation`: Validates incoming Bearer tokens at the edge against JWKS endpoints before forwarding traffic to the cluster.
- `restrict-ips`: Restricts traffic at the edge to designated CIDRs or references to `IPPolicy` resources.

### YAML Samples (≤15 lines each)

#### (a) Gateway with Hostname Listener
```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: ngrok-gw
  namespace: default
spec:
  gatewayClassName: ngrok
  listeners:
  - name: https
    hostname: "app.example.com"
    port: 443
    protocol: HTTPS
```

#### (b) HTTPRoute using ExtensionRef to TrafficPolicy
```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: api-route
spec:
  parentRefs: [{name: ngrok-gw}]
  rules:
  - matches: [{path: {type: PathPrefix, value: /api}}]
    filters:
    - type: ExtensionRef
      extensionRef:
        group: ngrok.com
        kind: TrafficPolicy
        name: jwt-auth-policy
    backendRefs: [{name: api-svc, port: 8080}]
```

#### (c) TrafficPolicy with JWT Validation
```yaml
apiVersion: ngrok.com/v1
kind: TrafficPolicy
metadata:
  name: jwt-auth-policy
spec:
  policy:
    on_http_request:
    - name: validate-jwt
      actions:
      - type: jwt-validation
        config:
          issuer_url: "https://auth.example.com/"
          audience: ["api.example.com"]
          http_header_name: "Authorization"
```

### Conformance & Licensing
- **License**: MIT License.
- **Conformance Status**: ngrok operator does not report conformance profiles on `GatewayClass.status.supportedFeatures`, nor has it submitted an official conformance report to `kubernetes-sigs/gateway-api`. It is not listed on the official SIG Network Gateway API implementations page.

---

## Tailscale operator

The Tailscale Kubernetes Operator (`tailscale.com`) integrates Kubernetes workloads with an authenticated WireGuard mesh (tailnet).

### Annotation Table

Tailscale defines its annotations in `tailscale.com/cmd/k8s-operator/sts.go`:

| Annotation Key | Target Kind | Purpose |
|---|---|---|
| `tailscale.com/expose` | `Service` | `"true"` triggers the operator to deploy a dedicated Tailscale proxy pod to expose the cluster service to the tailnet. |
| `tailscale.com/tags` | `Service`, `Connector`, `ProxyGroup` | Comma-separated Tailscale ACL tags assigned to the node (e.g. `tag:k8s,tag:prod`). Controls tailnet authorization. |
| `tailscale.com/hostname` | `Service` | Customizes the MagicDNS node name assigned to the service on the tailnet. |
| `tailscale.com/tailnet-ip` | `Service` | Specifies a target tailnet IP address for cluster egress services (replaces deprecated `tailscale.com/ts-tailnet-target-ip`). |
| `tailscale.com/tailnet-fqdn` | `Service` | Specifies a target tailnet MagicDNS FQDN for cluster egress services. |
| `tailscale.com/proxy-class` | `Service`, `Ingress` | References a `ProxyClass` CRD to customize pod specs, security contexts, resources, and nodeSelectors for proxy pods. |
| `tailscale.com/proxy-group` | `Service`, `Ingress` | References a `ProxyGroup` CRD to route ingress/egress traffic through a shared, highly-available StatefulSet of proxies. |
| `tailscale.com/funnel` | `Ingress` | `"true"` exposes the ingress publicly to the entire internet using Tailscale Funnel and automated public TLS certs. |
| `tailscale.com/http-redirect` | `Ingress` | `"true"` sets up port 80 to port 443 automatic HTTP-to-HTTPS redirects. |
| `tailscale.com/share-acme-account`| `ProxyGroup` | Opts in/out (`"true"`/`"false"`) of reusing a shared per-tailnet Let's Encrypt ACME account key. |
| `tailscale.com/experimental-forward-cluster-traffic-via-ingress` | `Ingress` | Configures iptables/nftables in the proxy so pods inside the cluster can resolve and reach the ingress via its MagicDNS name. |

### CRD Table

Tailscale operator CRDs belong to the `tailscale.com/v1alpha1` group.

| Kind | Scope | Key Spec Fields | Description |
|---|---|---|---|
| `Connector` | Cluster | `hostname`, `tags`, `proxyClass`, `subnetRouter.routes`, `exitNode`, `appConnector.routes` | Deploys a dedicated Tailscale node configured as a subnet router, exit node, or SaaS app connector. |
| `ProxyClass` | Cluster | `statefulSet.pod.spec` (resources, securityContext, affinity, tolerations, nodeSelector), `tailscaleConfig` | Reusable pod template configuration applied to auto-generated proxy StatefulSets. |
| `ProxyGroup` | Cluster | `type` (`ingress`, `egress`), `replicas`, `tags`, `proxyClass` | Defines a scalable, shared pool of Tailscale proxies for high-availability ingress or egress. |
| `ProxyGroupPolicy` | Namespaced | `proxyGroup`, `allowedServices`, `allowedIngresses` | RBAC control determining which namespaces and services can route traffic through a cluster-wide ProxyGroup. |
| `DNSConfig` | Cluster | `nameserver.image`, `magicDNS.enable` | Configures in-cluster CoreDNS forwarding to resolve Tailnet MagicDNS names inside Kubernetes pods. |
| `Recorder` | Cluster | `tags`, `storage`, `ui` | Provisions session recording nodes for Tailscale SSH session recording. |
| `Tailnet` | Cluster | `authKeySecret`, `oauthSecret`, `hostname` | Multi-tailnet configuration representing a cluster connection to a specific tailnet. |
| `PeerRelay` | Cluster | `replicas`, `tags`, `proxyClass` | Internal relay node configuration. |

### Identity & ACL Model: "Decoupled Tag Reference"

Tailscale enforces an **out-of-band identity architecture**:
1. **K8s Metadata Only**: Kubernetes manifests never define access rules, allowed users, or authorization logic. They only stamp tags via `tailscale.com/tags: "tag:api-service"`.
2. **Central Tailnet ACL Policy**: All identity evaluation is performed in the centralized Tailscale Policy File (managed in the Tailscale Admin Console or GitOps repository via HuJSON). For example:
   ```json
   "acls": [
     {"action": "accept", "src": ["group:engineering"], "dst": ["tag:api-service:80,443"]}
   ]
   ```
3. **WireGuard Layer Enforcement**: When a client initiates a connection, the Tailscale control plane evaluates the client's identity (user, group, device posture) against the tag stamped on the node. The Kubernetes cluster itself is never in the authentication critical path.

### Gateway API Status
- **Zero Support**: The Tailscale Kubernetes Operator contains no controllers, reconcilers, or watches for `gateway.networking.k8s.io` resources (`GatewayClass`, `Gateway`, `HTTPRoute`).
- Tailscale officially supports only Kubernetes `Service` (L4 proxying) and `Ingress` (with IngressClass `tailscale.com/ts-ingress`).

---

## Azure AGC and Other Cloud-Edge Gateway API Implementations

Azure Application Gateway for Containers (ALB Controller) is the canonical reference for an operator controlling a cloud-managed L7 data plane outside the Kubernetes cluster.

### Azure ALB Architecture & Deployment Modes
- **Data Plane**: Managed Azure L7 Application Gateway for Containers (proxies live in an Azure-managed infrastructure subnet, peering into the AKS cluster's CNI network).
- **Deployment Strategies**:
  1. *Managed deployment*: The ALB controller provisions and manages the Azure load balancer resource dynamically when an `ApplicationLoadBalancer` CRD is created in Kubernetes.
  2. *Bring Your Own (BYO) deployment*: An Azure administrator creates the ALB resource in Azure CLI/Terraform, and the Kubernetes `Gateway` resource binds to it via annotations.

### Annotations (`alb.networking.azure.io/*`)
- `alb.networking.azure.io/alb-id`: (BYO Mode) Specifies the Azure Resource Manager ID of the Application Gateway for Containers resource.
- `alb.networking.azure.io/alb-name`: (Managed Mode) Specifies the name of the ALB resource to create in Azure.
- `alb.networking.azure.io/alb-namespace`: (Managed Mode) Specifies the namespace where the parent `ApplicationLoadBalancer` CRD resides.

### CRD and Policy Attachment Model (`alb.networking.azure.io/v1`)
Azure AGC strictly implements GEP-713 Policy Attachment for advanced L7 capabilities:
- `ApplicationLoadBalancer` (Namespaced): Defines associations (subnets) and status conditions for the managed Azure LB.
- `RoutePolicy` (Namespaced, targetRef: `HTTPRoute`): Attaches custom request timeouts and session affinity policies directly to Gateway API routes.
- `HealthCheckPolicy` (Namespaced, targetRef: `Service`): Configures active HTTP/HTTPS/gRPC health probe intervals, unhealthy thresholds, and match status codes for backend pods.
- `BackendTLSPolicy` (Namespaced, targetRef: `Service`): Configures TLS validation, SNI, and trusted root CA certificates for connections between Azure ALB and backend pods.
- `FrontendTLSPolicy` (Namespaced, targetRef: `Gateway` listener): Configures mTLS client certificate verification (`caCertificateRef`) and allowed SANs on frontend listeners.
- `BackendLoadBalancingPolicy` (Namespaced, targetRef: `Service`): Configures load balancing algorithms: `round-robin`, `least-request`, `ring-hash`, or `load-aware`.

---

## Cloudflare-Specific Ingress Controllers

### 1. STRRL/cloudflare-tunnel-ingress-controller
A popular open-source ingress controller that binds Ingress resources to Cloudflare Tunnel via the Cloudflare API.

- **Annotations**:
  - `cloudflare-tunnel-ingress-controller.strrl.dev/backend-protocol`: Upstream protocol (`http`, `https`, `tcp`, `ssh`, `rdp`).
  - `cloudflare-tunnel-ingress-controller.strrl.dev/proxy-ssl-verify`: `"on"` or `"off"`.
  - `cloudflare-tunnel-ingress-controller.strrl.dev/origin-server-name`: SNI hostname for backend TLS handshake.
  - `cloudflare-tunnel-ingress-controller.strrl.dev/http-host-header`: Rewrites the `Host` header sent to backends.
  - `cloudflare-tunnel-ingress-controller.strrl.dev/disable-dns-management`: `"true"` prevents the controller from creating Cloudflare CNAME DNS records.
  - `cloudflare-tunnel-ingress-controller.strrl.dev/connect-timeout`, `tls-timeout`, `tcp-keepalive`, `keepalive-connections`, `keepalive-timeout`, `no-happy-eyeballs`, `http2-origin`, `disable-chunked-encoding`.

- **Access Support (ADR 0001)**:
  - Rejected inline annotations for Access policies (due to flat-string expressiveness limits, silent fail-open risk on typos, and future incompatibility with Gateway API).
  - Adopted a GEP-713 policy attachment CRD: `CloudflareAccess` (`cloudflare-tunnel-ingress-controller.strrl.dev/v1alpha1`).
  - Decoupled policy content: `spec.policies` references reusable Access policy names created in the Cloudflare Dashboard / Terraform. The controller automatically provisions the Access Application for the Ingress hostname and binds the referenced policies.

- **Gateway API & In-Cluster Data Plane Decision (ADR 0002)**:
  - Identifies that native Cloudflare Tunnel ingress rules support only Hostname and Path. Gateway API core conformance requires methods, headers, query parameters, and filters.
  - **Decision**: A pure cloudflared tunnel cannot conform to Gateway API. Architecture must use an in-cluster proxy deployment (e.g. Envoy) paired with cloudflared acting solely as an L4/L7 transport pipe.

### 2. Lexfrei/cloudflare-tunnel-gateway-controller
An officially verified, conformant (v1.6.1) implementation of the Kubernetes Gateway API for Cloudflare Tunnel.

- **Architecture**: Runs an in-process L7 reverse proxy embedded inside the cloudflared process using cloudflared's `OverrideProxy` hook (via a lightweight cloudflared fork).
- **Function**: Cloudflare API is used only for DNS and tunnel setup. All incoming HTTP requests passing through the tunnel are intercepted by the local proxy, enabling 100% compliant Gateway API path matching (exact/prefix/regex), header/query matching, rewrites, redirects, mirroring, and CORS without relying on Cloudflare edge limitations.
- **CRDs (`gateway.cf.k8s.lex.la/v1alpha1`)**: `GatewayClassConfig`, `GatewayConfig`, `ExternalBackend`.
- **Annotations**: Uses internal digests (`cf.k8s.lex.la/tunnel-token-hash`, `cf.k8s.lex.la/auth-token-hash`) to trigger graceful rolling reloads of the proxy upon token rotation.

### 3. Official Cloudflare Presence
- **No Official Operator**: Cloudflare does not offer an official Kubernetes operator or Gateway API implementation. The legacy `cloudflare/cloudflare-ingress-controller` (2018) is archived. All modern integrations are community-developed.

---

## Edge Implementations in the Official Implementations List

As of September 2026, the official SIG Network Gateway API Implementations registry (`https://gateway-api.sigs.k8s.io/implementations/`) lists the following SaaS / Cloud Edge implementations:

| Implementation | Type / Edge Infrastructure | Stated Conformance Status | Notes |
|---|---|---|---|
| **Lexfrei's Cloudflare Tunnel Gateway Controller** | SaaS Edge Connector (Cloudflare Tunnel + in-process L7 proxy) | **Conformant v1.6.1** | The only conformant Cloudflare Tunnel implementation on the official list. |
| **Google Kubernetes Engine (GKE) Gateway Controller** | Managed Cloud Edge (Google Cloud External/Internal Anycast L7 LBs) | **Conformant v1.6.0** | Full HTTP, TLS, and multi-cluster routing at Google Edge. |
| **AWS Load Balancer Controller** | Managed Cloud Edge (AWS Application Load Balancer / NLB) | **Partially Conformant v1.6.1** | Translates Gateway resources into AWS ALB/NLB configurations. |
| **Amazon EKS (AWS Gateway API Controller)** | Managed Cloud Mesh/Edge (Amazon VPC Lattice) | **Partially Conformant v1.4.0** | Integrates Gateway API with VPC Lattice service networks. |
| *ngrok-operator* | SaaS Edge Outbound Connector (ngrok Cloud Edge) | *Unlisted* | Full Gateway API v1 implementation in codebase, but no official conformance report submitted upstream. |
| *Azure Application Gateway for Containers (ALB)* | Managed Cloud Edge (Azure ALB) | *Unlisted on web index* | Full implementation of Gateway API v1 and GEP-713 policies; self-hosted documentation. |

---

## Lessons for an Edge-Hosted Gateway API Implementation

### 1. Ingress Rule Expressiveness Ceiling vs. HTTPRoute
- **The Problem**: Tunnel configurations on edge SaaS (Cloudflare Tunnel `config.ingress`, AWS NLB) only evaluate coarse attributes like hostname and URL prefix. Gateway API HTTPRoute requires header matches, query parameter matches, HTTP methods, and complex filter pipelines (`URLRewrite`, `RequestHeaderModifier`).
- **The Lesson**: Attempting to implement HTTPRoute purely at the SaaS edge either fails conformance or artificially constrains users. Successful conformant implementations (Lexfrei, STRRL ADR 0002) treat the outbound tunnel as pure transport and terminate requests on an in-cluster L7 proxy (Envoy or embedded Go proxy) that enforces HTTPRoute rules.

### 2. TLS Listener Semantics & Port Realities
- **The Problem**: Gateway API assumes the controller binds local TCP ports (e.g. 80, 443, 8443) and can optionally terminate TLS using local `kubernetes.io/tls` Secrets. Edge SaaS networks operate on public anycast IP backbones where ports are strictly limited to 80/443, and TLS is terminated at the global edge.
- **The Lesson**:
  - Ports other than 80 and 443 should be rejected or documented as restricted.
  - Listener TLS mode `Passthrough` cannot work over an HTTP tunnel.
  - Edge certificates are managed by the SaaS platform. `certificateRefs` must either be ignored with a clear condition message (`ListenerReasonResolvedRefs: False` or `Accepted: True` with informative condition) or uploaded via cloud API (as ngrok does for custom domains).

### 3. Status Addresses (`status.addresses`)
- **The Problem**: Edge SaaS systems do not assign stable public IPv4/IPv6 addresses to a Kubernetes cluster pod.
- **The Lesson**: Always use `AddressType: Hostname`. Populate `status.addresses[].value` with the canonical DNS entry users must target:
  - For Cloudflare Tunnel: `<tunnel-id>.cfargotunnel.com` or the proxied public hostname.
  - For ngrok: `<id>.ngrok-cname.com` or the assigned edge domain.

### 4. Conformance Test Suite Obstacles
- **The Problem**: The standard `kubernetes-sigs/gateway-api` conformance suite sends HTTP probe requests to the Gateway's `status.addresses` using synthetic hostnames like `foo.example.com` or `test.org`. An edge SaaS platform (Cloudflare, ngrok) drops or returns 404/403 for hostnames not registered in the customer's account zone.
- **The Lesson**: To run the official test suite against a real edge:
  - Tests requiring foreign `Host` headers must be explicitly skipped or rewritten via a custom test runner (as documented in STRRL ADR 0002).
  - Alternatively, controllers provide a cluster-internal test loop where conformance tests hit the in-cluster proxy directly.

### 5. Identity-Aware Access: Policy Attachment vs. External Reference
- **The Lesson**:
  - Never use raw Ingress/Route annotations for complex identity policies (e.g. Cloudflare Access, ngrok OAuth). Flat string annotations lack schema validation, fail open on typos, and do not integrate with RBAC.
  - For policies configured inside Kubernetes, use **GEP-713 Policy Attachment** (`CloudflareAccess` or `TrafficPolicy`) attaching to `Gateway` or `HTTPRoute`.
  - To avoid duplicating complex SaaS policy schemas in CRDs, follow STRRL and Tailscale's pattern: let the CRD simply reference the name or tag of a centrally managed policy (e.g. `spec.policies: ["internal-team-policy"]` or `tailscale.com/tags: ["tag:prod"]`), delegating identity evaluation to the SaaS control plane.

---

## Sources
- ngrok Kubernetes Operator Repository: https://github.com/ngrok/ngrok-operator
- ngrok Operator Documentation: https://ngrok.com/docs/k8s/
- ngrok Traffic Policy Documentation: https://ngrok.com/docs/traffic-policy/
- Tailscale Kubernetes Operator Repository: https://github.com/tailscale/tailscale/tree/main/cmd/k8s-operator
- Tailscale Kubernetes Operator Documentation: https://tailscale.com/kb/1236/kubernetes-operator
- Azure Application Gateway for Containers Overview & API Specifications: https://learn.microsoft.com/en-us/azure/application-gateway/for-containers/
- STRRL Cloudflare Tunnel Ingress Controller: https://github.com/STRRL/cloudflare-tunnel-ingress-controller
- STRRL ADR 0001 (Cloudflare Access Policy Attachment CRD): https://github.com/STRRL/cloudflare-tunnel-ingress-controller/blob/master/docs/adr/0001-cloudflare-access-policy-attachment-crd.md
- STRRL ADR 0002 (Gateway API In-Cluster Data Plane): https://github.com/STRRL/cloudflare-tunnel-ingress-controller/blob/master/docs/adr/0002-gateway-api-in-cluster-data-plane.md
- Lexfrei Cloudflare Tunnel Gateway Controller: https://github.com/lexfrei/cloudflare-tunnel-gateway-controller
- Kubernetes Gateway API Implementations Registry: https://gateway-api.sigs.k8s.io/implementations/

---

## Open Questions / Gaps
- **Cloudflare Access Rule Synchronization**: Neither STRRL nor Lexfrei currently synchronizes deep Access rule logic (e.g., specific SAML attributes or device posture checks) directly from Kubernetes CRD fields; both rely on referencing pre-created policy names. Whether a pure CRD can cleanly capture the rapidly evolving Cloudflare Access expression language without constant drift remains an open question for Flareway.
- **cloudflared In-Process Override vs. Envoy Sidecar**: Lexfrei uses a custom Go fork of `cloudflared` with an `OverrideProxy` hook for in-process L7 routing. Whether Flareway should maintain a fork of `cloudflared`, run an upstream `cloudflared` container forwarding to a local Envoy container, or run `cloudflared` as a standalone binary in the same pod remains a key decision for the orchestrator.
- **WARP Private Networking Gateway Integration**: While Tailscale supports private mesh routing via subnet routers, neither ngrok nor existing Cloudflare tunnel controllers map Gateway API TCPRoute/UDPRoute directly onto Cloudflare WARP client routing.
