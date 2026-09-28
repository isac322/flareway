# Security model: grants, Access, fail closed

On a shared cluster, Kubernetes RBAC and `CloudflareAccount` grants must both allow every operation. When Flareway cannot prove a state, it blocks traffic.

Platform teams can hand a Cloudflare account to many namespaces without handing each one the whole account.

## Two authorization layers

Kubernetes RBAC decides who can create and change Gateway API and Flareway objects, and what the controller itself can read and write. `CloudflareAccount.spec.grants` decides what a namespace may do with a Cloudflare account: which hostnames, zones, exposures, backends, policy references, and private-route objects it may use.

An operation proceeds only when both layers allow it. Deny is the default:

- A namespace that matches no grant is denied.
- One matching grant must permit every part of an operation. Flareway never combines permissions from two grants to allow a request.

## Account grants

A grant selects namespaces with a label selector and lists what those namespaces may use. [`config/samples/flareway_v1alpha1_cloudflareaccount.yaml`](../../config/samples/flareway_v1alpha1_cloudflareaccount.yaml) declares two grants: one for a tenant namespace and one for a platform namespace. This tenant grant lets the `default` namespace publish public hostnames under `example.com` and reference shared Access objects, but not create them:

```yaml
grants:
- namespaceSelector:
    matchLabels:
      kubernetes.io/metadata.name: default
  hostnames:
  - "*.example.com"
  zones:
  - example.com
  exposures:
  - Public
  unprotectedHostnames:
  - app.example.com
  - public.example.com
  accessPolicyRefs: Allowed
  accessCustomPageRefs: Allowed
  backends:
    namespaces: Same
    kinds:
    - Service
  platformObjects: Denied
```

| Field | Boundary |
|---|---|
| `namespaceSelector` | The namespaces this grant governs. |
| `hostnames` | Exact hostnames, single-label wildcards, or `*`. `*.example.com` matches `api.example.com`, but not `example.com` or `deep.api.example.com`. |
| `zones` | Exact zone names, or `*`. |
| `exposures` | `Public`, `Private`, or both. A listener whose exposure is not listed is rejected. |
| `unprotectedHostnames` | Hostnames that may serve traffic without Cloudflare Access. Any other granted hostname must be protected. |
| `accessPolicyRefs`, `accessCustomPageRefs`, `devicePostureIntegrationRefs`, `accessStandaloneApplicationRefs` | Whether the namespace may reference platform-managed Access objects. Each defaults to `Denied`. |
| `privateRoutes` | Label selectors for the `NetworkRoute` and `HostnameRoute` objects the namespace may reference. Without it, those references are denied. |
| `backends` | Which backend Services a route may reach, on top of any `ReferenceGrant`: `Same` namespace (the default) or namespaces matching a `Selector`. Without it, every backend reference is denied. |
| `platformObjects` | Whether the namespace may create or manage platform-scoped objects: shared Access objects such as `AccessPolicy`, `AccessGroup`, `IdentityProvider`, `AccessCustomPage`, `DevicePostureRule`, and `ServiceToken`; private-network objects such as `VirtualNetwork`, `NetworkRoute`, and `WARPConnector`; device profiles; and Direct-mode `CloudflareTunnel`s. Defaults to `Denied`. |

Treat `unprotectedHostnames` as a security boundary. Add a hostname only when the platform intends to serve at least one route on it without Access. A public path carve-out under a protected parent also needs its hostname here, even though the parent path stays protected.

Leave `platformObjects: Denied` unless you trust the namespace to manage these shared account resources. The samples give that trust to one namespace, `flareway-platform`, whose grant sets `platformObjects: Allowed`, adds `Private` to `exposures`, and selects private routes by the label `flareway.bhyoo.com/private-route: platform`. Shared Access objects, private networking, WARP connectors, the Direct tunnel, and the private Gateway live there. Tenant namespaces keep `platformObjects: Denied` and reach the shared Access objects through `policyRef.namespace` and `customPageRefs[].objectRef.namespace`, which `accessPolicyRefs` and `accessCustomPageRefs` permit.

The grant fields are defined in the [API reference](../reference/api.md). The Cloudflare API token and the capabilities each feature needs are covered in [Connect a Cloudflare account](../get-started/connect-cloudflare.md).

## Authorize before provisioning

Flareway evaluates grants before it reads a credential Secret or calls the Cloudflare API. A denied request never reaches Cloudflare. The affected object reports a `False` condition with reason `RefNotPermitted` or `UnsupportedValue`, and the condition message names the gate that failed.

## Access enforcement

Attach an `AccessApplication` to a Gateway listener or `HTTPRoute`, and Flareway creates the Cloudflare Access application and its policy, reads the application's AUD tag, and verifies the Access JWT inside the cluster. Cloudflare Access checks the request at the edge. The Access JWT is then verified again at the origin: by `cloudflared` and Envoy for public hostnames, and by Envoy for private ones.

For a public protected hostname:

- `cloudflared` receives `originRequest.access` with the team name, the AUD tags, and `required: true` for each protected rule.
- Envoy runs a `jwt_authn` filter on that hostname's listener. It reads the token from the `Cf-Access-Jwt-Assertion` header or the `CF_Authorization` cookie and validates it against the keys at `https://<team auth domain>/cdn-cgi/access/certs`.

For a private (WARP) hostname, `cloudflared` has no ingress rule, so Envoy's `jwt_authn` filter is the origin check. That check depends on Cloudflare Gateway TLS decryption. Set `AccessApplication.spec.originJWT.assumeGatewayTLSDecryption: true` to confirm that decryption is on; until you do, Flareway keeps the private hostname blocked and reports the Gateway `Programmed=False` with reason `Pending`.

A protected hostname is blocked until it is ready. While the AUD tag or the team domain is unknown, both `cloudflared` and Envoy answer that hostname with HTTP `403`. You never copy an AUD tag by hand; Flareway stores it in a controller-owned Secret.

Origin verification is controlled by `AccessApplication.spec.originJWT.mode`:

- `Required` is the default. Requests without a valid Access JWT for the application's AUD are refused at the origin.
- `Disabled` is an explicit opt-out. Flareway still creates the Access application and forwards traffic once the application is ready, but the origin does not check the JWT.

Routes with no `AccessApplication` carry no JWT check. A granted hostname can serve such routes only if it is listed in `unprotectedHostnames`.

[Protect a route with Cloudflare Access](../get-started/protect-with-access.md) walks through a full example.

## What "fail closed" means

When Flareway cannot prove that the security and routing state has reached the data plane, it blocks traffic instead of guessing.

| Situation | What Flareway does |
|---|---|
| The API token Secret is missing or the token is invalid | `CloudflareAccount` reports `CredentialsValid=False`. |
| The token is active but zone or Zero Trust organization reads fail | `CredentialsValid=True`, and `Accepted=False` with reason `CloudflareAPIError`; the message names the failed read. |
| A grant or reference rule denies an operation | The affected object reports it in a condition and message. An `HTTPRoute` backend denied by a `ReferenceGrant` or the account's backend grant reports `ResolvedRefs=False`, reason `RefNotPermitted`, while its `Accepted` condition can stay `True`. |
| A remote object carries a foreign ownership marker or fails its adoption expectations | The object reports `Accepted=False`, reason `Conflict`. Flareway does not overwrite it. |
| xDS, `cloudflared`, DNS, an Access AUD, or a private prerequisite is not ready | The Gateway reports `Programmed=False`, reason `Pending`, and the message names the missing step. |
| An existing DNS record has a foreign ownership comment | `DNSReady=False`; Flareway leaves the record alone. |
| Teardown cannot finish in order | The finalizer stays and the object reports `CleanupBlocked=True`. |
| A service-token create was sent but the token is not yet visible | `Ready=False`, reason `RecoveryPending`; Flareway re-lists instead of creating a second token. |

Deleting an `AccessApplication` never makes a protected route public. The route stays blocked unless no Access application targets it and the account grant lists the hostname in `unprotectedHostnames`. While an application is being deleted, Flareway keeps a blocked entry for every hostname it protected.

Access revocation is not instant. Cloudflare propagates a revoked session to its edge in about 20 to 30 seconds. `cloudflared` and Envoy validate JWT signatures without calling Cloudflare, so a signed token stays valid at the origin until its `exp` time.

[Troubleshooting](../operations/troubleshooting.md) lists every fail-closed condition with the action that clears it.

## Credentials

- Use a scoped API token for each `CloudflareAccount`, never the Global API Key.
- Flareway never writes API tokens to status, Events, or request logs.
- Tunnel connector tokens, WARP Connector tokens, Access AUD tags, and service-token client secrets live only in Kubernetes Secrets.
- Credentials that Cloudflare returns only once, such as a service-token secret or a SaaS application client secret, are written to a controller-owned Secret before the object reports ready. Flareway cannot recover them from Cloudflare later, so restore a lost one from its original source or rotate it deliberately.

## `Programmed` means converged

A Gateway reports `Programmed=True` only after the tunnel is healthy, Envoy has applied the configuration in every active data-plane Pod, `cloudflared` has applied the desired tunnel configuration, and, with managed DNS, the DNS record exists. A listener waiting for its Access application reports `Programmed=False` with reason `Pending`.

## Controller RBAC and tenant duties

The Helm chart grants the controller access to:

- Gateway API resources and their status subresources;
- Flareway CRDs, their status, and finalizers;
- Secrets for Cloudflare credentials, tunnel tokens, xDS certificates, Access AUDs, listener certificates, and service tokens;
- Deployments, Services, ConfigMaps, PodDisruptionBudgets, NetworkPolicies, Pods, EndpointSlices, Namespaces, Events, and leader-election Leases.

The controller's ServiceAccount lives in `flareway-system`, and a ClusterRoleBinding gives it cluster-wide permissions because `GatewayClass`, `GatewayClassConfig`, `CloudflareAccount`, namespace grants, cross-namespace backend checks, and Gateway API watches all cross namespace boundaries. Do not bind the controller's ClusterRole to tenant users.

Split tenant RBAC by duty:

- Application teams manage `Gateway` and `HTTPRoute` in their own namespaces.
- Security teams manage `AccessApplication` and namespaced Access references.
- Platform teams own `CloudflareAccount`, its grants, account-wide settings, and shared private-network resources.
- Only Secret administrators read credential, AUD, tunnel-token, and service-token Secrets.

[Ownership, adoption, and teardown](ownership-and-adoption.md) covers how Flareway claims and releases Cloudflare objects. To report a vulnerability, follow the [security policy](../SECURITY.md).
