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
