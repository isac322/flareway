# Troubleshooting Flareway

Start with status conditions and Events: `Programmed=False`, `Conflict`, `CleanupBlocked`, and `CredentialsValid=False` each name the gate that blocks traffic.

Flareway blocks traffic when it cannot prove that the requested security and routing state has reached the data plane. These commands show where each object stopped:

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
| `CleanupBlocked=True` | A finalizer is preserving teardown order. Remove remaining `NetworkRoute`/`HostnameRoute` references or restore the Cloudflare permission needed for deletion. Do not strip the finalizer unless you accept remote leaks or exposed traffic. If you strip an `AccessApplication` finalizer, the controller still removes that application's AUD handoff and private-tunnel ledger Secrets from the operator namespace, but the remote Cloudflare objects are left behind. |
| `Ready=False`, reason `RecoveryPending` | A ServiceToken create attempt was journaled as dispatched but the remote token is not yet visible, or a zone-scope recovery is waiting for the retiring token's deletion to be confirmed. The controller treats absence from the remote list as unknown, so it blocks and re-lists instead of issuing a blind create or rotate. This bounded wait is intended fail-closed behavior. |
| `PrivateListenerDegraded=True` | A private listener uses the Pod-IP fallback instead of loopback. Verify the NetworkPolicy before treating it as ready. |

Deleting an `AccessApplication` never makes a protected route public. The route remains blocked unless no Access application targets it and `CloudflareAccount.spec.grants[].unprotectedHostnames` explicitly permits the hostname.

Deleting an `AccessApplication` that never reached a Cloudflare write, such as one in a namespace its `CloudflareAccount` does not grant, skips remote cleanup and releases the finalizer. After Flareway has attempted a Cloudflare write for it, deletion needs the namespace grant. If the grant was removed, the object reports `CleanupBlocked=True` with `RefNotPermitted` until the grant is restored.

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

Drift detection has its own metrics; see [Drift detection and Cloudflare API budget](freshness-and-drift.md#metrics).

## Debug logging

The controller logs JSON to stderr at `info` by default. Enable `debug` to see `V(1)` entries such as the per-request `Cloudflare API request completed` lines:

```sh
helm upgrade flareway oci://ghcr.io/isac322/charts/flareway \
  --version <chart-version> \
  --namespace flareway-system \
  --reuse-values \
  --set logging.level=debug
```

Use the chart version you already run; the `CHART` column of `helm list --namespace flareway-system` shows it. Set `logging.level=info` the same way to turn debug output off.

Filter the JSON logs with `jq`, for example:

```sh
kubectl -n flareway-system logs deployment/flareway-controller-manager -c manager | jq -cR 'fromjson? | select(.level == "error")'
```

Integer levels add more controller-runtime detail: `logging.level=1` enables `V(1)`, and integers `2` or higher also disable the production log sampler. The chart accepts integers `1` through `6`. The raw `--zap-log-level` flag accepts larger integers, but levels `8` and higher make client-go log API request and response bodies (truncated to 1024 bytes at `8` and 10240 bytes at `9`, complete from `10`), including Secret contents; do not use them outside isolated debugging.

Rare client-go (klog) lines keep klog's own text format (`I0923 12:00:00.000000 1 file.go:123] msg`), and gRPC's rare ERROR lines are not JSON either. The `-R` flag and `fromjson?` in the example above skip those lines; plain `jq` stops at the first non-JSON line.

The [Helm chart values](../../charts/flareway/README.md#logging) page lists every logging value.

## Access application checks

### Application type and variant

Both application resources require `spec.accountRef`, an immutable PascalCase `spec.type`, and exactly one matching variant:

- `AccessApplication`: `SelfHosted/selfHosted`, `SSH/ssh`, `VNC/vnc`, `RDP/rdp`, `MCP/mcp`, or `ProxyEndpoint/proxyEndpoint`;
- `AccessStandaloneApplication`: `SaaS/saas`, `Bookmark/bookmark`, `Infrastructure/infrastructure`, `AppLauncher/appLauncher`, `WARP/warp`, `BISO/biso`, `DashSSO/dashSso`, or `MCPPortal/mcpPortal`.

If admission reports that a variant is missing or mismatched, change the discriminator and variant together. Do not replace a type with a lower-case Cloudflare wire value such as `self_hosted` or `app_launcher`.

`AccessApplication.targetRefs[]` accepts same-namespace `gateway.networking.k8s.io` `Gateway` and `HTTPRoute` references. `sectionName` selects a listener or named route rule. `pathScope` can narrow the compiled public region with `Exact` or `PathPrefix`; it cannot create a public destination without a target. Direct `destinations[]` entries must use one matching typed member. A `Private` entry requires exactly one of `networkRouteRef` or `hostnameRouteRef`.

### Account and zone scope

An empty `spec.zone` uses the account-scoped Access endpoint. A non-empty zone is resolved by exact DNS name from `CloudflareAccount.status.verified.zones`. If the zone is absent there, fix account token permissions or the zone name; do not copy a zone ID into the DNS-name field.

`RefNotPermitted` can also mean the matching account grant denies `accessPolicyRefs`, `accessCustomPageRefs`, `devicePostureIntegrationRefs`, `accessStandaloneApplicationRefs`, `platformObjects`, or the selected `privateRoutes`. For a private route, both the account grant selector and the route's `allowedNamespaces` must permit the consumer.

## Secret recovery

One-time values are not recoverable from Cloudflare and never appear in status:

- `ServiceToken` writes `CF-Access-Client-Id` and `CF-Access-Client-Secret`, plus previous keys during a rotation grace period; a pending create is journaled (see [ServiceToken create journal](#servicetoken-create-journal));
- SaaS application creation stores the generated client secret in the controller-owned Secret referenced by `status.saas.clientSecretRef`;
- SCIM HTTP Basic passwords, bearer tokens, OAuth client secrets, and Access service tokens come from Secret or `ServiceToken` references;
- identity-provider and posture-integration credentials use Secret key references;
- WARP Connector and Tunnel connector tokens use controller-owned Secrets.

For `IdentityProvider` SCIM, `spec.scimConfig.secretRef` is immutable after it is set. Flareway reserves the owned Secret before creating or enabling SCIM, journals ambiguous create responses, and verifies that the stored token is bound to the same remote provider ID. If the Secret destination must change, replace the resource deliberately.

If one of these Secrets is missing, restore it from the original secure source or create a deliberate rotation or replacement plan. Adoption does not rotate credentials, and the controller cannot reconstruct a create-only secret from status.

### ServiceToken create journal

A managed fresh create records its intent in a controller-owned journal Secret (`flareway-st-intent-<cr-uid>`) and reserves the credential destination before the remote create. The journal binds the CR UID, cluster UID, account UID and account ID, resolved zone ID, destination Secret, `spec.name`, and a per-attempt nonce; the remote create name is `flareway/<clusterUID>/<namespace>/<crUID>/<specName>-<nonce>`.

- `Ready=False`, reason `RecoveryPending`: a dispatched create is not yet visible in the remote list, or a zone-scope recovery is waiting for the retiring token's confirmed deletion. The controller re-lists and never re-creates blindly; the state resolves on its own once the remote becomes visible.
- `Ready=False`, reason `Conflict` on a pending attempt: the journal's identity tuple drifted (a `spec.zone`, `spec.accountRef`, `spec.name`, or `spec.secretRef` edit, or an account or cluster identity change), the journal or destination Secret is foreign-owned or corrupt, or remote candidates are ambiguous. Recovery is administrative: revert the drifted field, or delete and recreate the ServiceToken so a fresh journal is bound. Flareway never adopts an ambiguous or foreign token.
- Deleting a pending ServiceToken still cleans up journaled remote tokens even when `status.tokenId` is empty. If the journal is missing, a scoped prefix sweep runs; ambiguity or a failed remote delete keeps the finalizer with `CleanupBlocked` rather than leaking the token.
- After the status checkpoint the journal is reaped. A journal left behind after the checkpoint is reap-only and never grounds a resume or rotation.
- An established ServiceToken whose credential Secret is lost reports `SecretMissing` and never rotates or recreates on its own; restore the Secret from the original secure source or request an explicit rotation via `spec.rotation.requestedAt`.

Cloudflare response envelopes (`success`, `errors`, `messages`, `result`, pagination) and server-owned fields are absent from spec by design. Diagnose them through controller conditions and bounded status rather than adding untyped fields to manifests.

## Other symptoms

- A persistent `Conflict` on adoption or on a bypass child, a Tunnel owned by another Gateway, or teardown stuck at `CleanupBlocked`: see [Ownership, adoption, and teardown](../concepts/ownership-and-adoption.md).
- Admission rejects Gateway fields on a `Direct` tunnel, or a Direct ingress rule or DNS setting is invalid: see [Direct tunnels](../get-started/direct-tunnels.md).
- A private hostname does not resolve or connect over WARP, or a `WARPConnector` HA or route setting is rejected: see [Private services over WARP](../get-started/private-services-over-warp.md).
- Long streams end early at the edge: Cloudflare edge limits still apply, and their behavior with long streams has not been measured live. See [Limits and boundaries](../concepts/limits.md).
- Running the end-to-end suite: see [End-to-end test prerequisites](../../CONTRIBUTING.md#end-to-end-test-prerequisites).
