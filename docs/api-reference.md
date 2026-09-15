# Flareway API Reference

This reference describes the implemented `flareway.bhyoo.com/v1alpha1` parity surface. Generated CRDs in `config/crd/bases/` remain authoritative for validation, defaults, limits, and status schemas.

## Conventions

- Enum values use the spelling defined by the CRD schema. Lifecycle and discriminator enums are generally PascalCase; `ZeroTrustGatewayPolicy`, `ZeroTrustList`, and some device-profile fields retain Cloudflare's wire-native spelling.
- Resources that call Cloudflare require `spec.accountRef.name`.
- `managementPolicy` is `Managed` or `ObserveOnly`.
- `adoption.mode` is `None` or `AdoptById`. `AdoptById` requires an `externalRef`; matching a remote name is never enough.
- `deletionPolicy` is `Delete` or `Orphan`.
- A namespaced object reference contains `name` and an optional `namespace`; an omitted namespace means the referencing object's namespace.
- Secret values are accepted only through Secret references or written to controller-owned Secrets. Status never contains API tokens, client secrets, passwords, bearer tokens, Tunnel tokens, WARP Connector tokens, or Access AUDs.

## Shipped resource catalog

Flareway serves 22 CRD Kinds:

| Area | Kinds |
|---|---|
| Gateway and account | `GatewayClassConfig`, `CloudflareAccount`, `CloudflareTunnel` |
| Access applications | `AccessApplication`, `AccessStandaloneApplication` |
| Access dependencies | `AccessPolicy`, `AccessGroup`, `IdentityProvider`, `AccessCustomPage`, `DevicePostureRule`, `DevicePostureIntegration`, `AccessInfrastructureTarget`, `ServiceToken` |
| Private network | `VirtualNetwork`, `NetworkRoute`, `HostnameRoute`, `WARPConnector` |
| Device and organization | `DeviceProfile`, `DeviceSettings`, `ZeroTrustOrganization`, `ZeroTrustGatewayPolicy`, `ZeroTrustList` |

## Gateway class configuration

`GatewayClassConfig` is cluster-scoped and is referenced by a Gateway API `GatewayClass.parametersRef`. `spec.accountRef` is required in Cloudflare mode and must be omitted when `conformanceMode: true`.

The resource owns class defaults for the cloudflared `connector`, Envoy `proxy`, private-DNS sidecar, managed or external DNS, origin JWT mode, and the Gateway-safe `originRequest` subset. Conformance mode instead selects the direct data-plane Service type and performs no Cloudflare account operations.

## Scope and authorization

`CloudflareAccount` is cluster-scoped and defines the credential and tenant boundary:

```yaml
apiVersion: flareway.bhyoo.com/v1alpha1
kind: CloudflareAccount
metadata:
  name: production
spec:
  accountId: "0123456789abcdef0123456789abcdef"
  credentials:
    apiTokenSecretRef:
      name: cloudflare-api
      namespace: flareway-system
      key: token
  grants:
    - namespaceSelector:
        matchLabels:
          flareway.bhyoo.com/tenant: payments
      hostnames: ["*.example.com"]
      zones: ["example.com"]
      exposures: [Public, Private]
      unprotectedHostnames: ["health.example.com"]
      accessPolicyRefs: Allowed
      accessCustomPageRefs: Allowed
      devicePostureIntegrationRefs: Allowed
      accessStandaloneApplicationRefs: Allowed
      privateRoutes:
        networkRouteSelector: {}
        hostnameRouteSelector: {}
      backends:
        namespaces: Same
        kinds: [Service]
      platformObjects: Denied
```

A matching grant is required before a controller reads a referenced Secret or calls Cloudflare. Grants independently authorize hostname, DNS zone, listener exposure, reusable policy references, custom pages, posture integrations, standalone applications, private routes, platform objects, and Kubernetes backends.

Access applications and service tokens use the account endpoint when `spec.zone` is omitted. When `zone` is present, Flareway resolves its exact DNS name through `CloudflareAccount.status.verified.zones`; users do not place a zone ID in this field.

## Access applications

Cloudflare application types are split by Kubernetes ownership model.

| Kind | `spec.type` values |
|---|---|
| `AccessApplication` | `SelfHosted`, `SSH`, `VNC`, `RDP`, `MCP`, `ProxyEndpoint` |
| `AccessStandaloneApplication` | `SaaS`, `Bookmark`, `Infrastructure`, `AppLauncher`, `WARP`, `BISO`, `DashSSO`, `MCPPortal` |

Both Kinds require `accountRef`, immutable `type`, and exactly one variant matching the type.

### `AccessApplication`

`AccessApplication` is a GEP-713 Direct policy attached to Gateway API targets.

```yaml
apiVersion: flareway.bhyoo.com/v1alpha1
kind: AccessApplication
metadata:
  name: admin
  namespace: payments
spec:
  accountRef: {name: production}
  zone: example.com
  type: SelfHosted
  selfHosted: {}
  targetRefs:
    - group: gateway.networking.k8s.io
      kind: HTTPRoute
      name: admin
      sectionName: admin-rule
  pathScope:
    type: PathPrefix
    value: /admin
  application:
    name: payments-admin
    sessionDuration: 8h
    allowAuthenticateViaWarp: true
    autoRedirectToIdentity: true
    allowedIdpRefs:
      - name: corporate-oidc
    customPageRefs:
      - objectRef:
          name: access-denied
          namespace: flareway-system
    serviceAuth401Redirect: true
  policies:
    - policyRef:
        name: employees
        namespace: flareway-system
  originJWT:
    mode: Required
    audienceScope: Application
  bypass:
    children:
      - hostname: admin.example.com
        path: /admin/healthz
        externalRef: {applicationId: "existing-child-id"}
        adoption:
          mode: AdoptById
          expect: {name: existing-health-bypass}
        deletionPolicy: Orphan
  managementPolicy: Managed
  deletionPolicy: Delete
```

#### Targets and `pathScope`

`targetRefs[]` accepts same-namespace `gateway.networking.k8s.io` `Gateway` and `HTTPRoute` objects. `sectionName` selects a Gateway listener or named HTTPRoute rule. Public destinations are always compiled from these targets; the deprecated Cloudflare `self_hosted_domains` field is not exposed.

`pathScope` requires at least one target. It narrows the target-derived hostname to an `Exact` or `PathPrefix` path; omitted `type` defaults to `PathPrefix`. It creates a more-specific protection domain without changing the HTTPRoute's backend behavior.

`ProxyEndpoint` requires target references and does not accept direct destinations. Other attached application types require targets, destinations, or both.

#### Additional destinations

`destinations[]` is a discriminated union. Each item requires `type` and exactly one matching member.

| `type` | Matching member | Fields |
|---|---|---|
| `Private` | `private` | exactly one of `networkRouteRef` or `hostnameRouteRef`; optional `cidr`, `portRange`, `l4Protocol: TCP|UDP` |
| `ViaMCPServerPortal` | `viaMcpServerPortal` | `mcpServerId` |
| `Worker` | `worker` | `workerId` |
| `PreviewWorker` | `previewWorker` | `workerId` |
| `AllWorkers` | `allWorkers` | `{}` |
| `AllPreviewWorkers` | `allPreviewWorkers` | `{}` |

```yaml
spec:
  destinations:
    - type: Private
      private:
        networkRouteRef: {name: payments-cidr}
        cidr: 10.40.8.12/32
        portRange: "5432"
        l4Protocol: TCP
    - type: Worker
      worker: {workerId: "worker-id"}
```

The referenced route must cover the private destination. Both the matching account grant and the route's `allowedNamespaces` must authorize the application namespace.

#### Attached variants

- `SelfHosted`, `SSH`, `VNC`, and `MCP` use marker objects.
- `RDP` requires `rdp.targetCriteria[]`; every criterion uses `protocol: RDP` with `port` and non-empty `targetAttributes`.
- `ProxyEndpoint` uses `proxyEndpoint: {}` and target references only.

#### Origin JWT audience scope

`originJWT.mode` is `Required` by default; `Disabled` requires platform authorization. `audienceScope` defaults to `Application`:

- `Application` accepts only this application's AUD.
- `Hostname` accepts every ready application AUD for the compiled hostname and requires `mode: Required`.

Private listeners use Envoy JWT validation. When Gateway TLS decryption cannot be observed, `assumeGatewayTLSDecryption: true` records the platform's assertion; without proof or assertion, Flareway remains fail-closed.

#### Explicit bypass-child adoption

Flareway creates more-specific self-hosted child applications for public paths carved out below a protected parent. `status.bypassApplications[]` records each child and whether it was `Created`, `Recovered`, or `Adopted`.

To adopt a child, declare its normalized `hostname` and `path`, `externalRef.applicationId`, `adoption.mode: AdoptById`, and expected attributes. An `ObserveOnly` parent requires an external reference for every child. This preserves existing child IDs and AUDs during migration.

### Shared application settings

The `application` block is shared by attached and standalone applications. It covers:

- `name`, `sessionDuration`, `allowAuthenticateViaWarp`, `allowIframe`, `skipInterstitial`;
- `autoRedirectToIdentity`, `allowedIdpRefs`, `appLauncherVisible`;
- `serviceAuth401Redirect`, binding/HTTP-only/SameSite/path cookie settings;
- `optionsPreflightBypass` or `corsHeaders`;
- `readServiceTokensFromHeader`, custom deny message and URLs;
- `customPageRefs`, `eagerRedirectCookieSetting`, `logoUrl`;
- application MFA and OAuth authorization-server settings;
- outbound `scimConfig`;
- `useClientlessIsolationAppLauncherUrl` and user `tags`.

`AccessStandaloneApplication` type `WARP` is the exception: `application.name` is unsupported because Cloudflare owns the enrollment application's name. To adopt an existing enrollment, identify it with `externalRef.applicationId`, `adoption.mode: AdoptById`, and a non-empty `adoption.expect.name`.

`optionsPreflightBypass: true` and `corsHeaders` cannot be set together. `autoRedirectToIdentity: true` requires exactly one `allowedIdpRef`.

SCIM authentication is one of `HTTPBasic`, `OAuthBearerToken`, `OAuth2`, `AccessServiceToken`, or an ordered `multiple` list. Passwords, bearer tokens, and OAuth client secrets are Secret key references. `AccessServiceToken` refers to a managed `ServiceToken`. `scimConfig` also exposes `idpRef`, `remoteUri`, `deactivateOnDelete`, `enabled`, and ordered mappings with `schema`, `enabled`, `filter`, create/update/delete operations, `Strict|Passthrough`, and `transformJsonata`.

### `AccessStandaloneApplication`

Standalone applications use the same lifecycle, application settings, policy references, account/zone scope, and adoption model without Gateway targets.

```yaml
apiVersion: flareway.bhyoo.com/v1alpha1
kind: AccessStandaloneApplication
metadata:
  name: device-enrollment
  namespace: flareway-system
spec:
  accountRef: {name: production}
  type: WARP
  application: {}
  warp: {}
  policies:
    - policyRef: {name: managed-devices}
  managementPolicy: Managed
  deletionPolicy: Orphan
```

Variant fields:

| `type` | Variant contract |
|---|---|
| `SaaS` | `saas.authType: OIDC|SAML` and matching `oidc` or `saml` config; auth type is immutable |
| `Bookmark` | `bookmark.url`, optional `logoUrl` |
| `Infrastructure` | SSH `targetCriteria`, optional MFA, and inline `Allow` policies with SSH connection rules |
| `AppLauncher` | colors, logo, landing-page design, footer links, login-page behavior |
| `WARP` | `warp: {}` device-enrollment application |
| `BISO` | `biso: {}` Browser Isolation permissions application |
| `DashSSO` | `dashSso.domain` |
| `MCPPortal` | `mcpPortal.domain` and typed `destinations[]` |

SaaS OIDC supports grant types `AuthorizationCode`, `AuthorizationCodeWithPKCE`, `RefreshTokens`, `Hybrid`, and `Implicit`; scopes are `OpenID`, `Groups`, `Email`, and `Profile`. SaaS SAML supports typed NameID and attribute formats. A create-only SaaS client secret is written to a controller-owned Secret referenced by `status.saas.clientSecretRef` and is never copied into status.

## Access dependencies

### Policies and groups

`AccessPolicy.decision` is `Allow`, `Deny`, `NonIdentity`, or `Bypass`. `include` is required; `require` and `exclude` are optional. `AccessGroup` uses the same complete typed rule union and may nest groups through a group reference.

Policy attachments select either a managed `policyRef` or `externalRef.policyId`. Slice order defines remote precedence.

### Identity providers

`IdentityProvider.type` values are `OneTimePIN`, `AzureAD`, `SAML`, `Centrify`, `Facebook`, `GitHub`, `GoogleApps`, `Google`, `LinkedIn`, `OIDC`, `Okta`, `OneLogin`, `PingOne`, `Yandex`, and `Cloudflare`.

Provider credentials use `config.clientSecretRef`. `scimConfig` can enable directory synchronization, configure identity-update and deprovision behavior, and reference the controller-owned SCIM Secret. Status may contain bounded users, groups, and public SAML certificates, but never credentials.

`scimConfig.secretRef` becomes immutable after it is set. Flareway reserves that Secret before enabling SCIM and uses an ownership-bound journal to recover ambiguous Cloudflare create responses without creating a second provider. To move the credential, replace the `IdentityProvider` through an explicit migration instead of changing the reference in place.

### Service tokens

```yaml
apiVersion: flareway.bhyoo.com/v1alpha1
kind: ServiceToken
metadata:
  name: deployment-client
  namespace: payments
spec:
  accountRef: {name: production}
  name: deployment-client
  enabled: true
  duration: 8760h
  secretRef: {name: deployment-client}
  rotation:
    mode: Manual
    graceDuration: 24h
  deletionPolicy: Delete
```

The Secret uses `CF-Access-Client-Id` and `CF-Access-Client-Secret`. During a grace period it can also contain `CF-Access-Client-Id-Previous` and `CF-Access-Client-Secret-Previous`. `rotation.requestedAt` requests a manual rotation. `OnExpiry` refresh is account-scoped.

### Custom pages

`AccessCustomPage.type` is `IdentityDenied`, `Forbidden`, `Login`, or `Interstitial`. `html` contains the HTML/Liquid template; `contractVersion` selects Cloudflare's sanitized template contract.

### Device posture integrations

`DevicePostureIntegration.type` is `WorkspaceOne`, `CrowdstrikeS2S`, `Uptycs`, `Intune`, `Kolide`, `TaniumS2S`, `SentinelOneS2S`, or `CustomS2S`. Provider-specific URLs and IDs are plain fields; keys and client credentials use Secret key references.

### Device posture rules

`DevicePostureRule` owns one reusable posture check. `type` selects the typed `input` contract for file, application, WARP, firewall, OS, certificate, antivirus, serial-number, domain-joined, and supported integration-backed checks. Integration-backed types require `input.integrationRef`; `Firewall`, `CustomS2S`, and `ClientCertificateV2` enforce their type-specific required fields in the CRD schema. The resource also exposes platform matches, scheduling, expiration, explicit adoption, and deletion policy.

### Infrastructure targets

`AccessInfrastructureTarget` registers a hostname with IPv4, IPv6, or both. Each address chooses a namespaced `virtualNetworkRef` or an external `virtualNetworkId`, not both.

## Device enrollment settings

### `DeviceProfile`

`DeviceProfile` is the aggregate writer for one Cloudflare device profile. `profile.kind` is `Default` or `Custom`; custom profiles require `match`, `precedence`, and `fields.name`, while the default profile cannot use `externalRef` or adoption. `splitTunnel.mode` is `Include` or `Exclude` and owns the complete static list plus selected `NetworkRoute`, `HostnameRoute`, private-hostname-range, and public `AccessApplication` sources. The same resource owns fallback domains, DNS search suffixes, service mode, tunnel protocol, virtual-network access, and the remaining mutable profile fields.

### `DeviceSettings`

`DeviceSettings` is a namespaced account singleton and must be named `default`. It manages Gateway proxy, UDP proxy, root-certificate installation, Zero Trust virtual IP, and disable-duration settings. Its default `managementPolicy` is `ObserveOnly`; status reports observed values and the exact non-secret changes Managed mode would apply.

## Tunnel configuration

### Gateway mode

`CloudflareTunnel.spec.configuration.mode` defaults to `Gateway`. The Gateway controller owns the complete Cloudflare configuration and may use these Gateway-mode overrides:

- `connector`: image, replicas, `Auto|QUIC|HTTP2`, grace period, resources;
- `proxy`: image, resources, stream idle timeout, concurrency;
- `privateDNS`: image and resources;
- `originRequest`: `connectTimeout`, `keepAliveTimeout`, `tcpKeepAlive`, `keepAliveConnections`, `noHappyEyeballs`, `disableChunkedEncoding`, and `http2Origin`, the subset valid for a loopback Envoy origin;
- `listeners[]`: listener name, `Public|Private`, optional virtual network, automatic hostname-route creation;
- `dns` and optional `managementToken.resources: [Logs]`.

Gateway ownership is sticky and bound to both `status.gatewayRef.name` and `status.gatewayUid`. A later Gateway cannot preempt the live owner. Flareway drains the previous owner’s connector before admitting a successor. `ObserveOnly` Tunnels never issue connector tokens or create connector Secrets, and a non-empty `status.deletedAt` blocks Gateway publication, addresses, private routing, and configuration writes while cleanup drains the data plane.

### Direct mode

`Direct` is an explicit whole-object alternative. It cannot be combined with Gateway-owned `connector`, `proxy`, `privateDNS`, Gateway-mode `originRequest`, or `listeners`.

```yaml
apiVersion: flareway.bhyoo.com/v1alpha1
kind: CloudflareTunnel
metadata:
  name: direct-origin
  namespace: platform
spec:
  accountRef: {name: production}
  tunnel: {name: direct-origin}
  configuration:
    mode: Direct
    direct:
      ingress:
        - hostname: app.example.com
          path: ^/api
          service: {https: {address: api.default.svc.cluster.local:8443}}
          originRequest:
            originServerName: api.internal
            http2Origin: true
            connectTimeout: 30
            tlsTimeout: 10
        - hostname: ssh.example.com
          service: {ssh: {address: sshd.default.svc.cluster.local:22}}
          originRequest:
            proxyType: Regular
            tcpKeepAlive: 30
        - service: {httpStatus: {code: 404}}
      originRequest:
        noHappyEyeballs: false
        keepAliveConnections: 100
        keepAliveTimeout: 90
      warpRouting:
        enabled: true
        connectTimeout: 30
        tcpKeepAlive: 30
        maxActiveFlows: 1000
  dns:
    mode: Managed
    proxied: true
    ttl: 1
```

Each ingress rule selects exactly one service:

- address services: `http`, `https`, `tcp`, `ssh`, `rdp`, `smb`;
- socket services: `unix`, `unixTLS`;
- built-ins: `helloWorld`, `httpStatus`, `bastion`.

The final rule must be a catch-all with no hostname or path. `originRequest.access` is valid for HTTP, HTTPS, Unix HTTP, and Unix TLS origins. `originRequest.ipRules` requires `bastion` or `proxyType: SOCKS5`.

The complete Direct `originRequest` surface is `access` (`audTags`, `teamName`, `required`), `caPool`, `connectTimeout`, `disableChunkedEncoding`, `http2Origin`, `httpHostHeader`, `keepAliveConnections`, `keepAliveTimeout`, `matchSNIToHost`, `noHappyEyeballs`, `noTLSVerify`, `originServerName`, `proxyType: Regular|SOCKS5`, `tcpKeepAlive`, `tlsTimeout`, and `ipRules`. `warpRouting` exposes `enabled`, `connectTimeout`, `tcpKeepAlive`, and `maxActiveFlows`.

### DNS

`dns.mode` is `Managed` or `External` and applies to both configuration modes. Managed DNS exposes `recordComment`, `proxied`, `ttl`, and `settings.ipv4Only|ipv6Only`.

- A proxied record requires automatic TTL (`1`).
- `ipv4Only` and `ipv6Only` are mutually exclusive.
- Either IP-family setting requires `proxied: true`.
- Flareway uses the DNS comment as the ownership ledger and does not overwrite a foreign record.

## WARP Connector and private routes

`WARPConnector` is a distinct Cloudflare Mesh connector without a Gateway data plane.

`spec.name` is trimmed at its edges before matching or creation; comparison remains case-sensitive, and the name is never an adoption key. A live connector with the same exact normalized name causes `Conflict` unless the object uses `adoption.mode: AdoptById`, supplies `externalRef.tunnelId`, and sets a non-empty `adoption.expect.name` that exactly matches the remote connector. A case difference also requires explicit adoption. For an interrupted create, Flareway recovers only from its controller-owned status checkpoint and only when exactly one live connector matches the checkpointed account, name, WARP Connector type, create-only HA capability, and candidate tunnel ID recorded by the observed HA configuration. Unknown HA configuration modes and user annotations cannot authorize recovery or adoption.

```yaml
apiVersion: flareway.bhyoo.com/v1alpha1
kind: WARPConnector
metadata:
  name: mesh-egress
  namespace: flareway-system
spec:
  accountRef: {name: production}
  name: mesh-egress
  highAvailability:
    enabled: true
    mode: Local
    local:
      vips:
        - {address: 10.40.0.10}
  managementPolicy: Managed
  deletionPolicy: Orphan
```

`highAvailability.enabled` is create-only. `mode` is `None`, `Disabled`, `AWS`, or `Local`. `AWS` requires `aws.fnrId`; `Local` requires `local.vips[]` and may declare `vipsPrevious[]`. `failover` contains a linked `clientId` and a changing `requestId`. The controller writes the connector token to a Secret and records only bounded clients, edge connections, HA state, and failover status.

`VirtualNetwork` owns one account-scoped virtual network with a remote `name`, default-network flag, and comment. Observe-only or managed adoption uses `externalRef.virtualNetworkId`; a managed external reference requires `AdoptById`. `NetworkRoute` and `HostnameRoute` can then select that network through `virtualNetworkRef`.

Private routes use a typed tunnel reference:

```yaml
apiVersion: flareway.bhyoo.com/v1alpha1
kind: NetworkRoute
metadata:
  name: payments-cidr
  namespace: platform
spec:
  accountRef: {name: production}
  network: 10.40.0.0/16
  tunnelRef:
    kind: WARPConnector
    name: mesh-egress
    namespace: flareway-system
  virtualNetworkRef: {name: production}
  allowedNamespaces:
    from: Selector
    selector:
      matchLabels:
        flareway.bhyoo.com/tenant: payments
  deletionPolicy: Orphan
```

`TunnelReference.kind` is `CloudflareTunnel` or `WARPConnector`; omission defaults to `CloudflareTunnel`. `NetworkRoute` and `HostnameRoute` both use this reference and `allowedNamespaces.from: Same|All|Selector`.

## Zero Trust organization, Gateway policies, and lists

### `ZeroTrustOrganization`

`ZeroTrustOrganization` is a namespaced singleton and must be named `default`. It manages an account- or zone-scoped Access organization, including session settings, WARP authentication, unmatched-request behavior, custom deny pages, login design, MFA and PIV requirements, user revocation, and account-scoped DoH authentication through a `ServiceToken` reference. `authDomain` is create-only. Cloudflare exposes no organization delete operation, so `deletionPolicy` is always `Orphan`.

### `ZeroTrustList`

`ZeroTrustList` owns one complete Cloudflare Gateway list and all of its items. `type` is `SERIAL`, `URL`, `DOMAIN`, `EMAIL`, or `IP`. Managed replacement and adoption are explicit; ObserveOnly status reports the item-level additions and removals that Managed mode would apply.

### `ZeroTrustGatewayPolicy`

`ZeroTrustGatewayPolicy` owns one Gateway rule. It accepts exactly one filter, `l4` or `dns`, plus a Cloudflare action, traffic expression, optional identity and device-posture expressions, typed rule settings, and references to same-namespace `ZeroTrustList` objects. DNS `override` and L4-only `l4_override` or `audit_ssh` actions are schema-restricted to the matching filter.

## Ownership and migration safety

Use this sequence when moving an existing remote object under Flareway:

1. Set `managementPolicy: ObserveOnly`, `externalRef`, and `deletionPolicy: Orphan`.
2. Resolve drift shown in conditions or bounded observed/would-apply status.
3. Set `managementPolicy: Managed`, `adoption.mode: AdoptById`, and `adoption.expect` values that identify the intended remote object.
4. Change `deletionPolicy` only after ownership is verified.

Use the same process for bypass-child applications. Do not switch an application's immutable `type`, infer a Tunnel mode, replace a typed route kind, or recreate a missing one-time Secret as part of adoption. These operations can change IDs, AUDs, or credentials and require a deliberate replacement plan.

The remote ownership ledger uses tags where Cloudflare supports tags, deterministic comments for DNS and private-network resources, prefixed names where only names exist, and status remote IDs. A foreign or ambiguous marker produces `Conflict`; the controller does not overwrite the object.

## Parity ledger and intentional exclusions

| Cloudflare API category | Kubernetes representation |
|---|---|
| create/update field | typed `spec` field or typed reference |
| create-only secret | controller-owned Secret or user-provided Secret reference |
| remote identity and mutable observation | bounded `status` |
| connection lists | bounded status collections |
| server-owned timestamps, generated domains/audiences, `read_only` | status only |
| HTTP `success`, `errors`, `messages`, `result` envelope | excluded |
| pagination and result-info | excluded |
| deprecated wire aliases | excluded; canonical fields only |

Envelope and read-only exclusions define ownership; they are not feature-availability statements. The controllers consume the envelope internally, surface actionable failures as conditions, and keep response metadata out of desired state.
