# Research Report: Kubernetes Gateway API Implementation Practices & Extension Patterns

**Date:** 2026-09-12  
**Target Focus:** Policy Attachment CRDs, `parametersRef`, `ExtensionRef` filters, Annotations, Identity/Auth attachment, and Remote Cloud Data Planes across production Gateway API implementations.

---

## Summary (10 bullets max)

1. **Clear Division of Extension Mechanisms**: Mature implementations partition vendor concerns strictly: `parametersRef` on GatewayClass/Gateway for data plane infrastructure/fleet provisioning; GEP-713 `targetRef`/`targetRefs` policies for operational traffic and security policies; `ExtensionRef` route filters for request/response mutations; and annotations predominantly for backward compatibility or cloud-provider metadata.
2. **Envoy Gateway Zero-Annotation Architecture**: Envoy Gateway enforces a zero-annotation paradigm on standard Gateway API resources, modeling all extensions via CRDs: `EnvoyProxy` (`parametersRef`), `ClientTrafficPolicy`, `BackendTrafficPolicy`, `SecurityPolicy`, `EnvoyExtensionPolicy` (GEP-713 `targetRefs`), `HTTPRouteFilter` (`ExtensionRef`), and `Backend` (custom `backendRef`).
3. **Plural `targetRefs` Transition (GEP-713)**: Modern implementations (Envoy Gateway, Istio 1.22+, NGINX Gateway Fabric v1alpha2) have migrated or are actively migrating from singular `targetRef` to `targetRefs []LocalPolicyTargetReferenceWithSectionName` using CEL validations (`(has(self.targetRef) && !has(self.targetRefs)) || ...`) to prevent CRD proliferation.
4. **Strict Namespace Scoping (ReferenceGrant)**: Cross-namespace policy targeting is universally rejected (Istio enforces `rule="self.size() == 0"` on namespace; Envoy Gateway requires same-namespace). GEP-713 specifies that any cross-namespace policy attachment must require a reciprocal `ReferenceGrant` or equivalent security handshake to mitigate the confused deputy problem.
5. **Merge and Override Models**: Hierarchical policy merging (Gateway -> Route) is implemented either through explicit `mergeType` (Envoy Gateway: `Replace`, `StrategicMerge`, `JSONMerge`), strict precedence order (GKE: single policy per target, oldest creation timestamp wins), or the GEP-713 defaults/overrides model.
6. **External Identity as Policy Attachment**: Identity and authentication (JWT, OIDC, ExtAuth, Basic/APIKey Auth) are universally modeled as policy attachments to Gateways or Routes (Envoy Gateway `SecurityPolicy`, Istio `RequestAuthentication` + `AuthorizationPolicy`, AWS VPC Lattice `IAMAuthPolicy`), decoupling authentication requirements from application developers' route definitions.
7. **Filter Chain Positioning via `ExtensionRef`**: Request/response transformations requiring inline pipeline execution use `HTTPRoute.spec.rules[].filters[].extensionRef` (Traefik `Middleware`, Kong `KongPlugin`, NGINX Gateway Fabric `SnippetsFilter`, Envoy Gateway `HTTPRouteFilter`).
8. **Remote Cloud Data Plane Address Modeling**: Remote and cloud-managed controllers (AWS ALB Controller, AWS VPC Lattice, GKE) model non-IP data planes by populating `Gateway.status.addresses` with `type: Hostname` (e.g., AWS ELB DNS names, Lattice service network domains) or by reconciling static cloud IPs using `spec.addresses[].type: NamedAddress`.
9. **Cloud Certificate & Domain Ownership**: Cloud controllers decouple TLS configuration from local Kubernetes secrets via annotations or listener options referencing cloud certificate managers (e.g., GKE's `networking.gke.io/certmap` annotation on Gateway and `networking.gke.io/pre-shared-certs` in listener TLS options).
10. **Unsupported Feature Signaling**: Implementations adhere to Gateway API condition conventions by setting `Accepted=False` with reasons `UnsupportedValue` or `Invalid` on rejected routes/listeners, complemented by published conformance matrices documenting unsupported fields (e.g., GKE's documented lack of regex path matching and TCP/UDP/TLS routes on classic load balancers).

---

## Per-implementation tables

### 1. Envoy Gateway (`gateway.envoyproxy.io`)

Envoy Gateway avoids annotations on standard Gateway resources. Infrastructure settings are attached via `parametersRef`, operational/security policies via GEP-713 `targetRefs`, and inline route transformations via `ExtensionRef`.

| CRD Kind | Attaches Via | Targetable Kinds | `sectionName` Support | Merge Semantics | Status Shape |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`EnvoyProxy`** (`v1alpha1`) | `parametersRef` on `GatewayClass` or `Gateway.spec.infrastructure.parametersRef` | `GatewayClass`, `Gateway` | No | Hierarchical merge: EnvoyGateway defaults < GatewayClass < Gateway. Governed by `mergeType` (`Replace`, `StrategicMerge`, `JSONMerge`). | Standard conditions in `status.conditions` |
| **`ClientTrafficPolicy`** (`v1alpha1`) | `targetRef` / `targetRefs` / `targetSelectors` | `Gateway`, `ListenerSet` | Yes (`Gateway.listeners[].name`) | Atomic per listener. Cannot be merged across Route levels. | GEP-713 `PolicyStatus` with `status.ancestors[]` (`conditions`: `Accepted`, `Programmed`) |
| **`BackendTrafficPolicy`** (`v1alpha1`) | `targetRef` / `targetRefs` / `targetSelectors` | `Gateway`, `HTTPRoute`, `GRPCRoute`, `TCPRoute`, `UDPRoute`, `Service` | Yes (`Gateway` listener, `Route` rule name) | Supports `mergeType` (`Replace` or patch merge into closest parent policy in route hierarchy). | GEP-713 `PolicyStatus` with `status.ancestors[]` |
| **`SecurityPolicy`** (`v1alpha1`) | `targetRef` / `targetRefs` / `targetSelectors` | `Gateway`, `HTTPRoute`, `GRPCRoute` | Yes (`Gateway` listener, `Route` rule name) | Configurable via `mergeType` (`Replace` is rejected by CEL on `SecurityPolicy`; merges with parent policy). | GEP-713 `PolicyStatus` with `status.ancestors[]` |
| **`EnvoyExtensionPolicy`** (`v1alpha1`) | `targetRef` / `targetRefs` / `targetSelectors` | `Gateway`, `HTTPRoute`, `GRPCRoute` | Yes (`Gateway` listener, `Route` rule name) | Merges into closest parent policy when `mergeType` is specified on xRoute targets. | GEP-713 `PolicyStatus` with `status.ancestors[]` |
| **`EnvoyPatchPolicy`** (`v1alpha1`) | `targetRef` | `GatewayClass`, `Gateway` | No | Applied in ascending order of `spec.priority`. | Standard conditions in `status.conditions` |
| **`HTTPRouteFilter`** (`v1alpha1`) | `ExtensionRef` in `HTTPRoute.spec.rules[].filters[]` | Referenced inline within `HTTPRouteRule` | N/A (inline filter) | Rule-scoped evaluation in the Envoy filter chain. | None (configured inline) |
| **`Backend`** (`v1alpha1`) | `backendRefs` in `HTTPRoute.spec.rules[].backendRefs[]` | Referenced as backend target | N/A | Endpoint resolution, dynamic resolver, fallback backends, TLS config. | Standard conditions |

*Envoy Gateway Annotations:* Envoy Gateway explicitly avoids custom annotations on `Gateway` and `HTTPRoute` objects. Infrastructure-level annotations are injected into managed pods/services via `EnvoyProxy.spec.provider.kubernetes.envoyService.annotations` and `envoyDeployment.annotations`.

---

### 2. GKE Gateway Controller (`networking.gke.io`)

GKE uses singular `targetRef` policies bound strictly within the same namespace. Cloud infrastructure and certificates rely on specific GKE annotations.

| CRD Kind | Attaches Via | Targetable Kinds | `sectionName` Support | Merge Semantics | Status Shape |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`GCPGatewayPolicy`** (`v1`) | Singular `targetRef` | `Gateway` (`gateway.networking.k8s.io`) | No | Single policy per Gateway. Configures `allowGlobalAccess`, `region`, `sslPolicy`. | `status.conditions[]` (`Attached=True/False`) |
| **`GCPBackendPolicy`** (`v1`) | Singular `targetRef` | `Service`, `ServiceImport`, `InferencePool` | No | Strict 1:1 binding. Oldest policy wins; conflicting policies get `Attached=False`, Reason: `Conflicted`. | `status.conditions[]` (`Attached`, `Reason: Conflicted`) |
| **`HealthCheckPolicy`** (`v1`) | Singular `targetRef` | `Service`, `ServiceImport`, `InferencePool` | No | Strict 1:1 binding. Oldest policy wins. | `status.conditions[]` (`Attached`) |
| **`GCPTrafficDistributionPolicy`** (`v1`) | Singular `targetRef` | `Service`, `ServiceImport` | No | Configures locality LB and session affinity. Strict 1:1 binding. | `status.conditions[]` (`Attached`) |

*GKE Gateway Annotations:*
- `networking.gke.io/certmap`: Placed on `Gateway.metadata.annotations`. References a Google Cloud Certificate Manager Certificate Map, bypassing `listeners[].tls`.
- `networking.gke.io/pre-shared-certs`: Placed in `Gateway.spec.listeners[].tls.options`. Comma-separated list of Google Cloud SSL Certificate names.
- `addresses[].type: NamedAddress`: Placed in `Gateway.spec.addresses[]`. Points to a pre-allocated Google Cloud static external/internal IP name.
- `addresses[].type: networking.gke.io/premium-ephemeral-ipv4-address`: Requests a Google Cloud Premium Tier ephemeral IP.

---

### 3. Kong Ingress Controller & Operator (`configuration.konghq.com` / `konghq.com`)

Kong employs a dual model: modern `ExtensionRef` filters alongside its legacy and widely used `konghq.com/*` annotations.

| CRD Kind | Attaches Via | Targetable Kinds | `sectionName` Support | Merge Semantics | Status Shape |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`KongPlugin` / `KongClusterPlugin`** (`v1`) | `ExtensionRef` filter OR `konghq.com/plugins` annotation | `HTTPRoute` rule (via filter), `Gateway`, `HTTPRoute`, `Service` (via annotation) | Filter: Rule-specific; Annotation: entire resource | Plugin precedence: Consumer > Route (HTTPRoute) > Service > Global. | Filter: None; CRD: `status.conditions` |
| **`KongUpstreamPolicy`** (`v1beta1`) | Annotation `konghq.com/upstream-policy` on `Service` | `Service` | No | Reusable across multiple Services; applies to generated Kong Upstreams. (Direct policy label applied). | `status.conditions[]` |
| **`GatewayConfiguration`** (`v1alpha1`) | `parametersRef` on `GatewayClass` | `GatewayClass` | No | Operator-level fleet provisioning (dataplane Deployment, Service, autoscaling). | Standard conditions |

*Kong Annotations on Gateway API Resources (`konghq.com/*`):*
- `konghq.com/plugins`: Attaches comma-delimited `KongPlugin` resources to `Gateway` or `HTTPRoute`.
- `konghq.com/override`: Overrides route-level upstream properties.
- `konghq.com/strip-path`: Boolean (`"true"`/`"false"`). Determines path-stripping behavior before forwarding to backends.
- `konghq.com/preserve-host`: Boolean. Forwards client `Host` header instead of backend hostname.
- `konghq.com/protocols`: Specifies allowed protocols (`http`, `https`, `grpc`, `grpcs`).
- `konghq.com/regex-priority`: Integer priority for regex path matching.
- `konghq.com/snis`: Comma-separated list of SNIs for TLS matching.
- `konghq.com/request-buffering` / `konghq.com/response-buffering`: Enables/disables I/O buffering.
- `konghq.com/connect-timeout` / `read-timeout` / `write-timeout`: Upstream timeout values in milliseconds.

---

### 4. Istio Gateway API Support (`istio.io` / `security.istio.io`)

Istio integrates its security and traffic management CRDs with Gateway API using `targetRefs`.

| CRD Kind | Attaches Via | Targetable Kinds | `sectionName` Support | Merge Semantics | Status Shape |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`RequestAuthentication`** (`security.istio.io/v1beta1`) | `targetRefs` (or `targetRef` / `selector`) | `Gateway`, `HTTPRoute`, `Service` (`gateway.networking.k8s.io`) | No (whole resource) | Hierarchical: Gateway level validates JWT; Route/Service level can override or add rules. | Standard conditions |
| **`AuthorizationPolicy`** (`security.istio.io/v1beta1`) | `targetRefs` (or `targetRef` / `selector`) | `Gateway`, `HTTPRoute`, `Service` | No (whole resource) | Additive RBAC: `CUSTOM` -> `DENY` -> `ALLOW`. Route-level policies evaluated in context. | Standard conditions |
| **`WasmPlugin`** (`extensions.istio.io/v1alpha1`) | `targetRefs` | `Gateway`, `HTTPRoute` | No | Priority-ordered execution (`spec.priority`). | Standard conditions |
| **`Telemetry`** (`telemetry.istio.io/v1alpha1`) | `targetRefs` | `Gateway`, `HTTPRoute` | No | Most-specific resource overrides less-specific (Route overrides Gateway). | Standard conditions |

*Istio Annotations on Gateway:*
- `networking.istio.io/service-type`: Controls the generated ingress Service type (`LoadBalancer`, `ClusterIP`, `NodePort`).
- `gateway.istio.io/listener-protocol`: Overrides listener protocol translation.
- `proxy.istio.io/config`: Injects custom Envoy proxy configurations into Gateway pods.

---

### 5. Cilium Gateway API (`cilium.io`)

Cilium relies on `GatewayClass.spec.parametersRef` for infrastructure provisioning and avoids custom policy attachment CRDs, strictly validating standard Gateway API fields.

| CRD Kind | Attaches Via | Targetable Kinds | `sectionName` Support | Merge Semantics | Status Shape |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`CiliumGatewayClassConfig`** (`v2alpha1`) | `parametersRef` on `GatewayClass` (`group: cilium.io`) | `GatewayClass` | No | Global defaults for generated Gateway infrastructure (Service type, IP families, Envoy options). | `status.conditions[]` |

*Cilium Annotations:*
- `service.cilium.io/*` or cloud annotations (e.g. `service.beta.kubernetes.io/aws-load-balancer-*`) placed on generated Gateway services via `CiliumGatewayClassConfig.spec.service.annotations`.

---

### 6. NGINX Gateway Fabric (`gateway.nginx.org`)

NGINX Gateway Fabric strictly implements GEP-713 and GEP-2648, utilizing explicit CRD labels (`gateway.networking.k8s.io/policy: direct` and `gateway.networking.k8s.io/policy: inherited`).

| CRD Kind | Attaches Via | Targetable Kinds | `sectionName` Support | Merge Semantics | Status Shape |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`NginxProxy`** (`v1alpha2`) | `parametersRef` on `GatewayClass` or `Gateway.spec.infrastructure.parametersRef` | `GatewayClass`, `Gateway` | No | Replaces default NGINX deployment parameters (telemetry, metrics, client IP rewriting). | Standard conditions |
| **`ClientSettingsPolicy`** (`v1alpha1`, *inherited*) | Singular `targetRef` | `Gateway`, `HTTPRoute`, `GRPCRoute` | No | Inherited: Settings on Gateway apply to attached Routes unless overridden by Route-level policy. | GEP-713 `PolicyStatus` with `status.ancestors[]` |
| **`UpstreamSettingsPolicy`** (`v1alpha1`, *direct*) | Plural `targetRefs` (1-16) | `Service` | No | Direct: Atomic per Service. Multiple Services can be targeted by one policy. | GEP-713 `PolicyStatus` with `status.ancestors[]` |
| **`ObservabilityPolicy`** (`v1alpha2`, *direct*) | Plural `targetRefs` (1-16) | `HTTPRoute`, `GRPCRoute` | No | Direct attachment to routes for tracing configuration. | GEP-713 `PolicyStatus` with `status.ancestors[]` |
| **`SnippetsFilter`** (`v1alpha1`) | `ExtensionRef` in `HTTPRoute.spec.rules[].filters[]` | Referenced inline in route rules | N/A | Injects raw NGINX configuration snippets into generated location/server blocks. | Standard conditions |

---

### 7. Traefik (`traefik.io`)

Traefik implements Gateway API extension points exclusively via standard filters and backend references.

| CRD Kind | Attaches Via | Targetable Kinds | `sectionName` Support | Merge Semantics | Status Shape |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`Middleware`** (`v1alpha1`) | `ExtensionRef` filter in `HTTPRoute.spec.rules[].filters[]` | `HTTPRouteRule` | N/A | Sequential filter chain execution. | None |
| **`MiddlewareTCP`** (`v1alpha1`) | `ExtensionRef` filter in `TCPRoute.spec.rules[].filters[]` | `TCPRouteRule` | N/A | Sequential filter execution. | None |
| **`TraefikService`** (`v1alpha1`) | `backendRefs` in `HTTPRoute.spec.rules[].backendRefs[]` | `HTTPRouteRule` | N/A | Replaces standard Service backend with Traefik load-balancing/mirroring service. | None |

---

### 8. AWS Gateway Controllers (VPC Lattice & AWS Load Balancer Controller)

| CRD Kind | Attaches Via | Targetable Kinds | `sectionName` Support | Merge Semantics | Status Shape |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`IAMAuthPolicy`** (`application-networking.k8s.aws/v1alpha1`) | Singular `targetRef` (`NamespacedPolicyTargetReference`) | `Gateway`, `HTTPRoute`, `GRPCRoute` | No | Switches VPC Lattice auth mode to `AWS_IAM` and configures JSON IAM policy document. | `status.conditions[]` (`Programmed`, `Accepted`) |
| **`TargetGroupPolicy`** (`v1alpha1`) | Singular `targetRef` | `Service` | No | Configures VPC Lattice Target Group protocol, version, and health checks. | `status.conditions[]` |
| **`AccessLogPolicy`** (`v1alpha1`) | Singular `targetRef` | `Gateway`, `HTTPRoute`, `GRPCRoute` | No | Configures access log streaming to S3, CloudWatch, or Kinesis Firehose. | `status.conditions[]` |
| **`VpcAssociationPolicy`** (`v1alpha1`) | Singular `targetRef` | `Gateway` | No | Associates VPC Lattice Service Network with VPC and Security Groups. | `status.conditions[]` |
| **`LoadBalancerConfiguration`** (`eks.amazonaws.com`) | `parametersRef` on `GatewayClass` | `GatewayClass` | No | Governs AWS ALB/NLB provisioning, schemes, and subnets. | Standard conditions |

---

## Identity/auth attachment patterns

Mature implementations express route-level authentication requirements using policy attachment or `ExtensionRef`. Below are real-world patterns across platforms:

### 1. Envoy Gateway: `SecurityPolicy` (OIDC / JWT)
Attaches via GEP-713 `targetRefs` directly to the `HTTPRoute`, decoupling auth configuration from route logic.
```yaml
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: SecurityPolicy
metadata:
  name: route-oidc-auth
spec:
  targetRefs:
    - group: gateway.networking.k8s.io
      kind: HTTPRoute
      name: my-protected-route
  oidc:
    provider:
      issuer: https://accounts.google.com
      authorizationEndpoint: https://accounts.google.com/o/oauth2/v2/auth
      tokenEndpoint: https://oauth2.googleapis.com/token
    clientID: my-client-id
    clientSecret:
      name: oidc-client-secret
    redirectURL: https://app.example.com/oauth2/callback
    logoutPath: /logout
```

### 2. Istio: `RequestAuthentication` + `AuthorizationPolicy`
`RequestAuthentication` validates the JWT token; `AuthorizationPolicy` enforces that valid authentication exists. Both target the `HTTPRoute` via `targetRefs`.
```yaml
apiVersion: security.istio.io/v1beta1
kind: RequestAuthentication
metadata:
  name: jwt-auth
spec:
  targetRefs:
    - group: gateway.networking.k8s.io
      kind: HTTPRoute
      name: my-protected-route
  jwtRules:
    - issuer: https://auth.example.com
      jwksUri: https://auth.example.com/.well-known/jwks.json
---
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: require-jwt
spec:
  targetRefs:
    - group: gateway.networking.k8s.io
      kind: HTTPRoute
      name: my-protected-route
  action: ALLOW
  rules:
    - when:
        - key: request.auth.claims[iss]
          values: ["https://auth.example.com"]
```

### 3. Kong: `KongPlugin` via `ExtensionRef`
Attached as a discrete filter within the `HTTPRouteRule`, executing inline with routing decisions.
```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: my-protected-route
spec:
  parentRefs:
    - name: kong-gateway
  rules:
    - matches:
        - path: { type: PathPrefix, value: /api }
      filters:
        - type: ExtensionRef
          extensionRef:
            group: configuration.konghq.com
            kind: KongPlugin
            name: oidc-auth
      backendRefs:
        - name: app-svc
          port: 80
```

### 4. AWS VPC Lattice: `IAMAuthPolicy`
Attached via GEP-713 `targetRef` to require AWS Signature Version 4 (SigV4) IAM credentials to invoke the route.
```yaml
apiVersion: application-networking.k8s.aws/v1alpha1
kind: IAMAuthPolicy
metadata:
  name: require-iam-auth
spec:
  targetRef:
    group: gateway.networking.k8s.io
    kind: HTTPRoute
    name: my-protected-route
  policy: |
    {
      "Version": "2012-10-17",
      "Statement": [{
        "Effect": "Allow",
        "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
        "Action": "vpc-lattice-svcs:Invoke",
        "Resource": "*"
      }]
    }
```

### 5. Recommended Flareway Pattern: `AccessPolicy` (Cloudflare Zero Trust)
Modeled cleanly as a GEP-713 Policy Attachment targeting `HTTPRoute` or `Gateway`, mapping directly to a Cloudflare Access Application and Access Policies.
```yaml
apiVersion: gateway.flareway.io/v1alpha1
kind: AccessPolicy
metadata:
  name: team-access-policy
spec:
  targetRefs:
    - group: gateway.networking.k8s.io
      kind: HTTPRoute
      name: internal-dashboard
  application:
    sessionDuration: 24h
    autoRedirectToIdentity: true
  policies:
    - name: AllowTeam
      decision: allow
      include:
        - emailDomain: example.com
      require:
        - warp: true
```

---

## Conventions distilled

Surveying mature implementations reveals consistent architectural consensus regarding when to use each extension point:

```
+---------------------------------------------------------------------------------------+
|                                    GATEWAY CLASS                                      |
|  parametersRef: Infrastructure/Fleet Provisioning (EnvoyProxy, NginxProxy, CGCC)     |
+-------------------------------------------+-------------------------------------------+
                                            |
                                            v
+---------------------------------------------------------------------------------------+
|                                       GATEWAY                                         |
|  - spec.addresses: Static IP / NamedAddress (GKE NamedAddress, AWS ELB Hostname)      |
|  - annotations: Cloud Certs & Global LB knobs (certmap, pre-shared-certs)             |
|  - targetRefs: Listener/Client Policies (ClientTrafficPolicy, GCPGatewayPolicy)       |
+-------------------------------------------+-------------------------------------------+
                                            |
                                            v
+---------------------------------------------------------------------------------------+
|                                      HTTPROUTE                                        |
|  - ExtensionRef filters: Inline mutations (KongPlugin, SnippetsFilter, Middleware)    |
|  - targetRefs: Route Security & Traffic Policies (SecurityPolicy, IAMAuthPolicy)     |
+-------------------------------------------+-------------------------------------------+
                                            |
                                            v
+---------------------------------------------------------------------------------------+
|                                       BACKEND                                         |
|  - backendRefs: Custom backends (Envoy Backend, TraefikService)                      |
|  - targetRefs: Upstream policies (BackendTrafficPolicy, GCPBackendPolicy, Upstream)  |
+---------------------------------------------------------------------------------------+
```

### 1. `parametersRef` (GatewayClass & Gateway Infrastructure)
- **Concerns**: Fleet-wide and infrastructure provisioning (Deployment replicas, pod resources, Service types, compiler flags, proxy engine bootstrap, global telemetry sinks).
- **Evidence**: `EnvoyProxy` (Envoy Gateway), `NginxProxy` (NGINX), `CiliumGatewayClassConfig` (Cilium), `GatewayConfiguration` (Kong), `LoadBalancerConfiguration` (AWS).
- **Consensus**: Used strictly for *lifecycle and operational infrastructure* of the proxy fleet, never for application-level routing rules.

### 2. GEP-713 Policy Attachment (`targetRefs`)
- **Concerns**: Non-functional requirements, traffic management, and security boundaries (timeouts, retries, rate limiting, circuit breaking, mTLS, JWT, OIDC, RBAC, access logs).
- **Evidence**: `SecurityPolicy` and `ClientTrafficPolicy` (Envoy Gateway), `GCPBackendPolicy` and `GCPGatewayPolicy` (GKE), `IAMAuthPolicy` (AWS), `ClientSettingsPolicy` and `UpstreamSettingsPolicy` (NGINX).
- **Consensus**: Used when the policy must be managed independently of the route definition (e.g. by security or platform teams via RBAC), can span a hierarchy (Gateway down to Routes), or requires complex configuration structs that would pollute route specs.

### 3. `ExtensionRef` Filters (`HTTPRoute.spec.rules[].filters[]`)
- **Concerns**: Request-path modifications, inline header mutations, authentication checks that must execute at a specific index in the route processing pipeline, and server-native config injection.
- **Evidence**: `HTTPRouteFilter` (Envoy Gateway), `KongPlugin` (Kong), `Middleware` (Traefik), `SnippetsFilter` (NGINX).
- **Consensus**: Used when order of execution relative to other filters (e.g. rewrite before auth, or auth before header mutation) is critical, or when the transformation applies exclusively to an individual route rule.

### 4. Annotations
- **Concerns**: Cloud-provider metadata bindings (cert maps, pre-shared cert names, cloud network tiers) and legacy ingress migrations.
- **Evidence**: GKE uses `networking.gke.io/certmap` and `networking.gke.io/pre-shared-certs` because these point to out-of-cluster GCP Cloud resources that have no Kubernetes representation. Kong maintains `konghq.com/*` annotations primarily for backward compatibility with Ingress resources.
- **Consensus**: **Heavily discouraged** for traffic policy and security. In upstream Gateway API guidelines, annotations are considered anti-patterns for policy because they lack schema validation, cannot report status conditions, do not participate in RBAC cleanly, and cannot declare conflict resolution.

---

## Remote/cloud data planes

Implementations where the data plane runs in managed cloud infrastructure (GKE Cloud Load Balancing, AWS VPC Lattice, AWS ALB, Cloudflare Edge) face distinct modeling constraints compared to local in-cluster Envoy/NGINX proxies.

### 1. Hostname, IP, and DNS Ownership
- **GKE Gateway**: The GKE controller provisions Google Cloud external or internal Application Load Balancers.
  - **Static IP Provisioning**: Uses `spec.addresses` with `type: NamedAddress` pointing to a pre-allocated `compute.addresses` resource in GCP.
  - **Network Tiers**: Uses custom vendor address types in `spec.addresses[].type`, such as `networking.gke.io/premium-ephemeral-ipv4-address`.
  - **Status Reporting**: Once GCP allocates the forwarding rule VIP, `status.addresses` is populated with `type: IPAddress` and `value: <external-ipv4>`.
- **AWS VPC Lattice**: Data plane is a fully managed AWS VPC Lattice Service Network.
  - **Status Reporting**: A Gateway represents a Service Network; an `HTTPRoute` creates a VPC Lattice Service. The generated DNS name (`<route-id>.<region>.vpc-lattice-svcs.amazonaws.com`) is populated into `HTTPRoute.status.parents[].conditions` or Gateway status.
- **AWS Load Balancer Controller (ALB)**:
  - **DNS Hostname Assignment**: AWS ALBs do not provide static IP addresses; they provide canonical DNS hostnames.
  - **Status Reporting**: Populates `Gateway.status.addresses` with `type: Hostname` and `value: k8s-default-mygatewa-1234567890.us-west-2.elb.amazonaws.com`. Clients must create a CNAME or Route 53 Alias to this hostname.

### 2. Cloud Certificates and TLS Termination
Cloud data planes terminate TLS at the edge, where private keys cannot be stored in Kubernetes `Secret` objects:
- **Google Cloud Certificate Manager**: GKE supports `networking.gke.io/certmap: <map-name>` on the Gateway metadata, pointing to cloud-managed certificates that auto-renew at the Google edge. For legacy SSL certs, `networking.gke.io/pre-shared-certs` is specified in `listeners[].tls.options`.
- **AWS Certificate Manager (ACM)**: AWS LBC references ACM ARNs via annotations (`alb.ingress.kubernetes.io/certificate-arn`) or `tls.options`.

### 3. Architectural Implications for Flareway (Cloudflare Edge)
For Flareway, where Cloudflare Edge owns the public DNS, edge TLS certificates, and edge Anycast IP addresses, the mapping is direct:
- **Gateway Address**: `status.addresses` on Gateway should report `type: Hostname` pointing to `<tunnel-id>.cfargotunnel.com` (or Cloudflare Edge Anycast IPs).
- **DNS Provisioning**: When an `HTTPRoute` declares `hostnames: ["app.example.com"]`, Flareway creates or updates the Cloudflare DNS CNAME record pointing `app.example.com` to the Tunnel target.
- **TLS Configuration**: Handled natively by Cloudflare Universal SSL / Advanced Certificate Manager at the edge; `Gateway.spec.listeners[].tls` can validate edge termination mode (`Full`, `Strict`) via policy or options without requiring local TLS Secrets.

---

## Unsupported-feature signaling

Gateway API implementations handle unsupported capabilities through structured condition reporting and conformance documentation:

### 1. Standard Condition Reporting (`Accepted=False`)
When a controller encounters a resource requesting unsupported features, it must not crash or fail silently. Gateway API dictates:
- Set condition `Accepted: "False"`
- Use standardized reasons:
  - `Reason: UnsupportedValue`: When a field is recognized by the spec but unsupported by the data plane (e.g., regex path match on a data plane that only supports prefix/exact).
  - `Reason: Invalid`: When fields are malformed or semantically inconsistent.
  - `Reason: Conflicted`: When two policies target the same resource without an established merge strategy.

### 2. Partial Programming (`Accepted=True` with Warnings/Conditions)
- In Envoy Gateway and NGINX Gateway Fabric, if an `HTTPRoute` contains multiple rules and one rule is valid while another requests an unsupported filter, the route condition is reported as `Accepted: "True"`, but the rule status reflects `Programmed: "False"` with a specific diagnostic message, preventing full route failure.
- In GKE Gateway, when conflicting `GCPBackendPolicy` resources target the same Service, the older policy remains `Attached: "True"`, while the newer policy receives `Attached: "False"` with reason `Conflicted`.

### 3. Documented Feature Support Matrices
Implementations maintain explicit capability matrices to set user expectations:
- **GKE Gateway Docs**: Publishes a strict matrix contrasting `gke-l7-gxlb` (Global external Application Load Balancer), `gke-l7-regional-external-managed`, and `gke-l7-rilb`. GKE explicitly documents unsupported features:
  - No support for wildcard or regular expression path matching on classic load balancers (`gke-l7-gxlb`).
  - No support for `TCPRoute`, `UDPRoute`, or `TLSRoute` on L7 GatewayClasses.
  - Mutual exclusivity: Request redirect and URL rewrite cannot be configured simultaneously in the same rule.
- **Cilium Docs**: Explicitly documents Gateway API support status across releases, detailing unsupported features (e.g., lack of regex header matching, session affinity limits) and returning `Accepted=False` with `UnsupportedValue` if unsupported filter types are applied.

---

## Gateway API Project Recommendations & Guidelines

### 1. Annotations vs. Policy Attachment
From [GEP-713 (Metaresources and Policy Attachment)](https://gateway-api.sigs.k8s.io/geps/gep-713/#background):
> *"Avoid alternatives based on annotations which are often non-standardized, poorly documented, and generally hard to maintain, in favor of proper, expressive APIs (self-documenting intents) instead."*

The specification details that annotations suffer from critical design flaws in multi-tenant environments:
- **Lack of Schema Validation**: Annotations are unvalidated strings, shifting typo and syntax detection to runtime controller logs.
- **No Status Reporting**: Kubernetes annotations cannot report granular status, acceptance, conflicts, or ancestor binding progress back to the user.
- **Coarse-Grained RBAC**: Granting permission to edit an `HTTPRoute` allows editing all annotations on that route, preventing platform administrators from restricting who can configure sensitive policies (e.g. auth or rate limiting).
- **No Conflict Resolution**: Annotations lack structured mechanisms for merging, overriding, or resolving competing definitions across parent-child hierarchies.

### 2. Implementation-Specific API Groups
From Gateway API contributing and API extension guidelines:
- The API group `gateway.networking.k8s.io` is strictly reserved for upstream Kubernetes SIG-Network specifications.
- Vendors and implementations **must** place proprietary CRDs in their own API groups (e.g., `gateway.envoyproxy.io`, `networking.gke.io`, `configuration.konghq.com`, `gateway.nginx.org`, `application-networking.k8s.aws`).
- Direct Policy Attachment CRDs conforming to GEP-2648 / GEP-713 must include the label `gateway.networking.k8s.io/policy: direct` on the CRD metadata; Inherited policies must include `gateway.networking.k8s.io/policy: inherited`.

---

## Sources

- [Kubernetes Gateway API: GEP-713: Metaresources and Policy Attachment](https://gateway-api.sigs.k8s.io/geps/gep-713/)
- [Kubernetes Gateway API: GEP-2648: Direct Policy Attachment](https://gateway-api.sigs.k8s.io/geps/gep-2648/)
- [Envoy Gateway API Extensions Documentation](https://gateway.envoyproxy.io/docs/api/extension_types/)
- [Envoy Gateway Go API Definitions (`api/v1alpha1`)](https://github.com/envoyproxy/gateway/tree/main/api/v1alpha1)
- [GKE: Configure Gateway resources using Policies](https://cloud.google.com/kubernetes-engine/docs/how-to/configure-gateway-resources)
- [GKE: Deploying Gateways (Static IP, Certs, NamedAddress)](https://cloud.google.com/kubernetes-engine/docs/how-to/deploying-gateways)
- [Kong Ingress Controller Annotations & Route Translation Source Code](https://github.com/Kong/kubernetes-ingress-controller)
- [Kong Configuration CRD Types (`api/configuration/v1beta1`)](https://github.com/Kong/kubernetes-configuration)
- [Istio Security API Definitions (`RequestAuthentication`, `AuthorizationPolicy`)](https://github.com/istio/api/tree/master/security/v1beta1)
- [NGINX Gateway Fabric CRD Specifications (`apis/v1alpha1`, `apis/v1alpha2`)](https://github.com/nginx/nginx-gateway-fabric)
- [Traefik Kubernetes Gateway Provider Documentation](https://doc.traefik.io/traefik/routing/providers/kubernetes-gateway/)
- [AWS Application Networking (VPC Lattice) Gateway API Controller Reference](https://www.gateway-api-controller.eks.aws.dev/api-reference/)

---

## Open questions / gaps

1. **Cloudflare Tunnel Config Concurrency**: Cloudflare Tunnel ingress rules are serialized as an ordered list under a single configuration object via the Cloudflare API. When multiple `HTTPRoute` objects across different namespaces are reconciled concurrently, how should Flareway sequence and serialize updates to avoid race conditions and stale writes without causing API throttling?
2. **In-Pod L7 Proxy vs. Direct Cloudflared Routing**: Standard `cloudflared` native ingress rules support only hostname and path regex matching. Features mandated by Gateway API `HTTPRoute` (header matching, query parameter matching, method matching, request/response header mutations, path rewrites, and weighted traffic splits) cannot be performed by `cloudflared` alone. The orchestrator must decide whether Flareway runs an embedded Envoy/Envoy-light sidecar in the tunnel pod or restricts conformance to the subset of features natively expressible in Cloudflare Tunnel / Edge rules.
3. **Cross-Namespace Policy Authorization**: If an `AccessPolicy` in an infrastructure namespace targets an `HTTPRoute` in an application team's namespace (or vice versa), how strictly will Flareway enforce `ReferenceGrant`? While GEP-713 requires `ReferenceGrant` for cross-namespace targeting to prevent privilege escalation, some controllers (like Istio and Envoy Gateway) outright prohibit cross-namespace policy targets to eliminate the confused deputy problem entirely.
4. **Cloudflare Access Path-Level Granularity**: Cloudflare Access Applications can be scoped to domains or specific path prefixes (e.g. `app.example.com/admin*`), but session tokens are scoped to the domain cookie. Attaching different Access Policies to different `HTTPRoute` rules on the same hostname requires careful alignment with Cloudflare Access Application path-matching limitations.
5. **WARP Split-Tunnel Device Profiles**: Device profile split-tunnel include/exclude lists in Cloudflare Zero Trust are organization-wide or profile-wide single-writer objects. Mapping dynamic Kubernetes Service CIDRs to WARP private network routes will require a centralized aggregator controller rather than per-route reconciliation.
