# Troubleshooting Flareway

Start with status conditions and Events. Flareway blocks traffic when it cannot prove that the requested security and routing state has reached the data plane.

```sh
kubectl get gateway,httproute -A
kubectl get cloudflareaccount,cloudflaretunnel -A
kubectl get accessapplication -A
kubectl describe gateway -n <namespace> <name>
kubectl describe cloudflaretunnel -n <namespace> <name>
kubectl describe accessapplication -n <namespace> <name>
```

## Fail-closed conditions

| Observation | Meaning and action |
|---|---|
| `CloudflareAccount` `CredentialsValid=False` | The Secret is absent, the token is invalid, or the token lacks a read permission. Fix the Secret reference or token scope. |
| `Accepted=False`, reason `RefNotPermitted` | A namespace grant, `ReferenceGrant`, backend grant, policy reference grant, or private-route namespace rule denied the reference. Fix authorization; do not widen unrelated grants. |
| `Accepted=False`, reason `Conflict` | The remote object's ownership marker, expected adoption attributes, DNS record owner, or another policy writer conflicts. Identify the current owner before changing `managementPolicy` or adoption. |
| `Programmed=False`, reason `Pending` | xDS has not been acknowledged, the data plane is not ready, cloudflared has not applied the desired version, DNS is absent, an Access AUD is unavailable, or a private prerequisite is missing. Read the condition message for the exact gate. |
| `ConfigApplied=False` | Compare `CloudflareTunnel.status.configVersion.desired` and `.applied`; inspect data-plane Pods and cloudflared `/config` reachability. Flareway does not mark the Gateway programmed until every active Pod converges. |
| `DNSReady=False` | The zone is not granted, the zone was not discovered, or an existing record has a foreign ownership comment. Flareway omits DNS tags and will not overwrite a foreign record. |
| `CleanupBlocked=True` | A finalizer is preserving teardown order. Remove remaining `NetworkRoute`/`HostnameRoute` references or restore the Cloudflare permission needed for deletion. Do not strip the finalizer unless you accept remote leaks or exposed traffic. |
| `PrivateListenerDegraded=True` | A private listener uses the Pod-IP fallback instead of loopback. Verify the NetworkPolicy before treating it as ready. |

Deleting an `AccessApplication` never makes a protected route public. The route remains blocked unless no Access application targets it and `CloudflareAccount.spec.grants[].unprotectedHostnames` explicitly permits the hostname.

## Events

Flareway emits these warning reasons only when entering the corresponding condition state:

- `Conflict`: ownership, adoption, or remote-writer conflict;
- `CleanupBlocked`: ordered cleanup cannot advance;
- `SecurityBlocked`: forwarding was denied because the required security state was not proven.

Event messages are fixed and sanitized. They do not contain API tokens, tunnel tokens, service-token secrets, or Access AUDs.

```sh
kubectl get events -A --field-selector reason=Conflict
kubectl get events -A --field-selector reason=CleanupBlocked
kubectl get events -A --field-selector reason=SecurityBlocked
```

## Metrics

When `metrics.enabled=true`, the chart exposes the controller metrics Service. Secure serving defaults to enabled.

| Metric | Labels | Meaning |
|---|---|---|
| `flareway_reconcile_total` | `controller`, `result` | Reconcile outcomes by controller |
| `flareway_cloudflare_requests_total` | `service`, `status` | Cloudflare API requests by service and response status |
| `flareway_cloudflare_ratelimited_total` | none | Requests rejected or delayed by Cloudflare rate limiting |
| `flareway_gateway_programmed` | `gateway` | Whether a Gateway is currently programmed |
| `flareway_config_version` | `gateway`, `kind=desired|applied` | Desired and applied tunnel configuration versions |

Alert on sustained reconcile errors, rate limiting, a programmed gauge of `0`, or a desired/applied version gap. The metrics NetworkPolicy admits namespaces matching `metrics: enabled` by default; adjust `networkPolicy.metrics.namespaceSelector` for the monitoring namespace.

## Ownership and adoption

`managementPolicy: Managed` permits writes. `ObserveOnly` requires an `externalRef` and never claims an object by name. To adopt an existing remote object, set `externalRef`, `adoption.mode: AdoptById`, and expected attributes. Flareway compares the remote ID and expectation before setting `status.ownershipVerified`.

A name match is not ownership proof. If `Conflict` persists, compare:

- the Kubernetes object's UID and status remote ID;
- the remote tag, comment, or Flareway name prefix;
- `adoption.expect.name` or `.domain`;
- other Terraform, GitOps, or controller writers.

Keep shared Terraform-owned policies and identity providers as `ObserveOnly` with `deletionPolicy: Orphan`.

## Access and Tunnel parity checks

### Application type and variant

Both application resources require `spec.accountRef`, an immutable PascalCase `spec.type`, and exactly one matching variant:

- `AccessApplication`: `SelfHosted/selfHosted`, `SSH/ssh`, `VNC/vnc`, `RDP/rdp`, `MCP/mcp`, or `ProxyEndpoint/proxyEndpoint`;
- `AccessStandaloneApplication`: `SaaS/saas`, `Bookmark/bookmark`, `Infrastructure/infrastructure`, `AppLauncher/appLauncher`, `WARP/warp`, `BISO/biso`, `DashSSO/dashSso`, or `MCPPortal/mcpPortal`.

If admission reports that a variant is missing or mismatched, change the discriminator and variant together. Do not replace a type with a lower-case Cloudflare wire value such as `self_hosted` or `app_launcher`.

`AccessApplication.targetRefs[]` accepts same-namespace `gateway.networking.k8s.io` `Gateway` and `HTTPRoute` references. `sectionName` selects a listener or named route rule. `pathScope` can narrow the compiled public region with `Exact` or `PathPrefix`; it cannot create a public destination without a target. Direct `destinations[]` entries must use one matching typed member. A `Private` entry requires exactly one of `networkRouteRef` or `hostnameRouteRef`.

### Account and zone scope

An empty `spec.zone` uses the account-scoped Access endpoint. A non-empty zone is resolved by exact DNS name from `CloudflareAccount.status.verified.zones`. If the zone is absent there, fix account token permissions or the zone name; do not copy a zone ID into the DNS-name field.

`RefNotPermitted` can also mean the matching account grant denies `accessPolicyRefs`, `accessCustomPageRefs`, `devicePostureIntegrationRefs`, `accessStandaloneApplicationRefs`, `platformObjects`, or the selected `privateRoutes`. For a private route, both the account grant selector and the route's `allowedNamespaces` must permit the consumer.

### Bypass-child adoption

Flareway creates a more-specific child Access application when a protected parent contains a public carve-out. Existing children are never adopted by hostname or name alone. Declare the normalized `hostname` and `path` under `spec.bypass.children[]`, set `externalRef.applicationId`, and use `adoption.mode: AdoptById` with expected attributes. An `ObserveOnly` parent needs an `externalRef` for every declared child.

If a child reports `Conflict`, compare the remote application ID, normalized path, expected name/domain, and Flareway ownership tags. Do not delete the protected parent to clear a child conflict; that widens the outage and can change the parent AUD.

### Gateway and Direct Tunnel ownership

`CloudflareTunnel.spec.configuration.mode` defaults to `Gateway`. In that mode, the Gateway controller owns the complete remote configuration and may use `connector`, `proxy`, `privateDNS`, Gateway-mode `originRequest`, and `listeners`.

`Direct` mode is explicit whole-object ownership. Put rules under `configuration.direct.ingress`, and configure top-level `originRequest` and `warpRouting` there. A Direct rule selects exactly one service: `http`, `https`, `tcp`, `ssh`, `rdp`, `smb`, `unix`, `unixTLS`, `helloWorld`, `httpStatus`, or `bastion`. The final rule must omit hostname and path. `originRequest.access` is valid only for HTTP-family origins; `ipRules` requires `bastion` or `proxyType: SOCKS5`.

If admission says Direct mode cannot use Gateway fields, remove the Gateway-owned fields or switch the mode back to `Gateway`. Do not copy generated Gateway ingress into Direct mode while a Gateway still references the Tunnel.

Gateway-mode ownership is UID-bound and sticky. If a second Gateway reports that another Gateway owns the Tunnel, do not force a handoff by changing names or timestamps. Remove or delete the current owner, then wait for its connector Deployment and Pods to drain before the successor is admitted. A remote soft-delete sets `status.deletedAt`; Flareway keeps ownership provenance for cleanup but blocks xDS, connector scale-up, addresses, private routes, and further Tunnel configuration.

DNS is shared by both modes. For Managed DNS, a proxied record requires `ttl: 1`; `settings.ipv4Only` and `settings.ipv6Only` are mutually exclusive and require `proxied: true`.

### WARP Connector and typed routes

`NetworkRoute.spec.tunnelRef` and `HostnameRoute.spec.tunnelRef` require `name` and accept `kind: CloudflareTunnel|WARPConnector` plus an optional `namespace`; omitted `kind` defaults to `CloudflareTunnel`. `CloudflareTunnel` owns a Gateway data plane. `WARPConnector` owns a separate Mesh connector, token Secret, bounded client status, HA configuration, and explicit failover requests.

For WARP Connector HA, `AWS` requires `highAvailability.enabled: true` and `aws.fnrId`; `Local` requires enabled HA and at least one `local.vips` address. `highAvailability.enabled` is create-only. A failover request needs a linked `clientId` and a new `requestId`.

### Secret recovery

One-time values are not recoverable from Cloudflare and never appear in status:

- `ServiceToken` writes `CF-Access-Client-Id` and `CF-Access-Client-Secret`, plus previous keys during a rotation grace period;
- SaaS application creation stores the generated client secret in the controller-owned Secret referenced by `status.saas.clientSecretRef`;
- SCIM HTTP Basic passwords, bearer tokens, OAuth client secrets, and Access service tokens come from Secret or `ServiceToken` references;
- identity-provider and posture-integration credentials use Secret key references;
- WARP Connector and Tunnel connector tokens use controller-owned Secrets.

For `IdentityProvider` SCIM, `spec.scimConfig.secretRef` is immutable after it is set. Flareway reserves the owned Secret before creating or enabling SCIM, journals ambiguous create responses, and verifies that the stored token is bound to the same remote provider ID. Replace the resource through a deliberate migration if the Secret destination must change.

If one of these Secrets is missing, restore it from the original secure source or create a deliberate rotation/replacement plan. Adoption does not rotate credentials, and the controller cannot reconstruct a create-only secret from status.

Cloudflare response envelopes (`success`, `errors`, `messages`, `result`, pagination) and server-owned fields are intentionally absent from spec. Diagnose them through controller conditions and bounded status rather than adding untyped fields to manifests.

## Teardown

Managed Tunnel teardown is ordered:

1. public ingress becomes `403` and private virtual hosts become deny-all;
2. managed DNS records are removed;
3. connector Pods drain and stop;
4. Access applications are marked target-not-found and deleted only when their own policy permits it;
5. private routes must release the Tunnel;
6. the managed Tunnel is deleted last.

A failure keeps the finalizer and reports `CleanupBlocked`. Restore access or remove the blocking reference, then let reconciliation resume.

## Private WARP listeners

A private listener must use `HTTPS`, include a valid `certificateRefs` Secret, and have a matching `CloudflareTunnel.spec.listeners[]` entry with `exposure: Private`. Flareway binds Envoy to the Gateway listener's declared port, not to an internal `1844x` port. Cloudflare forwards the original private destination port, so using another port would break the WARP L4 destination and the Access `portRange` contract.

Private hostname routing also requires:

- `DeviceSettings.spec.gatewayProxyEnabled: true`;
- `DeviceSettings.spec.gatewayUdpProxyEnabled: true`;
- a `HostnameRoute` or `NetworkRoute` targeting the Tunnel;
- an Include-mode profile that includes the private hostname ranges when Include mode is used;
- no overlap between a hostname route and a fallback DNS suffix;
- Gateway TLS decryption, or `AccessApplication.spec.originJWT.assumeGatewayTLSDecryption: true`, when private origin JWT verification is required;
- a compatible WARP client and Cloudflare plan.

The local CoreDNS sidecar behavior is measured, but a live Cloudflare edge/WARP run has not verified whether Edge accepts a `127.0.0.1` private-hostname answer. D-11 remains live-blocked. Do not claim private hostname e2e support from envtest alone.

## Streaming

`HTTPRoute` `timeouts.request: 0s` and `proxy.streamIdleTimeout: 1h` configure the origin data plane for long streams. They do not remove Cloudflare Edge limits. The planned D-03 e2e case records a 150-second SSE stream and a request whose first byte is delayed by 120 seconds. That live edge measurement is currently blocked, so no release claim should state those cases passed.

## End-to-end test prerequisites

The e2e suite requires a dedicated test account and zone:

- `FLAREWAY_E2E_CF_API_TOKEN`
- `FLAREWAY_E2E_CF_ACCOUNT_ID`
- `FLAREWAY_E2E_ZONE`
- optional `FLAREWAY_E2E_KUBECONFIG`
- `FLAREWAY_E2E_LABELS` (default `public,access`)
- `FLAREWAY_E2E_WARP_DEVICE=1` only on a registered WARP runner
- optional `FLAREWAY_E2E_WARP_UNREGISTERED_DNS_SERVER`
- `FLAREWAY_E2E_DEVICE_PROFILE_KIND` and explicit `FLAREWAY_E2E_ALLOW_DEFAULT_PROFILE=1` before mutating the default profile

Use a dedicated account because e2e creates and deletes tunnels, DNS records, Access applications, policies, and private-network objects. Missing WARP runner or plan capability must be recorded as blocked, not passed or silently skipped.
