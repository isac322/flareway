# Drift detection and Cloudflare API budget

Flareway skips Cloudflare reads for converged objects and runs one periodic sweep for out-of-band edits, keeping API traffic inside the account rate limit.

## The trade-off

Flareway gives up detection speed to save Cloudflare reads. Changes made through Kubernetes apply at once, because they bump the object's generation and force a fresh read. Out-of-band changes, meaning any edit made outside Flareway in the Cloudflare dashboard, through Terraform, by another operator, or by a person, are detected after a bounded delay.

The delay depends on the kind's freshness grade and on whether the sweep is running; the [detection bounds](#content-confirmation) are listed below. Conditions, events, ownership rules, and fail-closed rules are unaffected.

## What `status.appliedAt` means

`status.appliedAt` records when `status.appliedHash` was last written, so it changes only when the desired state changes. On a `CloudflareTunnel`, `status.configVersion.appliedAt` changes only when a configuration is written to Cloudflare. A re-verify that finds Cloudflare already matching does not touch status, so a converged object produces no status writes and wakes no other controllers.

The time of the last re-verify is kept in operator memory. After a restart or leader change it is gone, and each object's first pass reads Cloudflare again unless its hash was recorded within the last TTL.

References from an `AccessApplication` to Cloudflare objects it does not own (`externalRef` policies, external identity providers and custom pages, and `ObserveOnly` policies and identity providers) are checked on the same schedule: only on passes that go to Cloudflare anyway. A deleted reference is found within the TTL, and the application stops being `Programmed`.

## Freshness grades

Every Cloudflare-backed kind carries a grade chosen by how directly a stale judgement affects a security or traffic outcome. The canonical table lives in `internal/freshness/grades.go`. Both the reconciler gate and the sweep read it, so a kind's read TTL and its drift-detection period always agree.

| Grade | Flag | Default | Kinds |
|---|---|---|---|
| T0 | none | always fresh | Reads before destructive writes, ownership and adoption claims, reads inside the tunnel configuration lock, and all `ObserveOnly` observation. Never gated, not tunable. |
| T1 | `--freshness-authz` | `60s` | `AccessApplication`, `AccessStandaloneApplication`, `AccessPolicy`, `AccessGroup`, `AccessCustomPage`, `AccessInfrastructureTarget`, `ServiceToken`, `IdentityProvider` |
| T2 | `--freshness-traffic` | `300s` | `CloudflareTunnel`, `Gateway` tunnel configuration (`CloudflareTunnelConfig`), DNS records, `ZeroTrustGatewayPolicy`, `ZeroTrustList`, `VirtualNetwork`, `NetworkRoute`, `HostnameRoute` |
| T3 | `--freshness-indirect` | `1800s` | `DeviceProfile`, `DeviceSettings`, `DevicePostureRule`, `DevicePostureIntegration`, `ZeroTrustOrganization`, `WARPConnector` |
| T4 | `--freshness-display` | `0` | Display-only reads. `0` means no periodic read. |

`CloudflareAccount` has no grade. Its remote calls are the resource's own liveness and authorization evidence rather than convergence reads, and they run on a ten-minute cycle.

The manager rejects a negative duration and requires `--freshness-authz` ≤ `--freshness-traffic` ≤ `--freshness-indirect` among the positive values. A grade set to `0` disables that grade's read-skip gate and sweep loops (retaining the watch-driven or periodic behavior below) and is exempt from that ordering.

### Choosing a profile

| Profile | T1 / T2 / T3 | Character |
|---|---|---|
| Conservative | `30s` / `60s` / `600s` | Fastest detection; smallest saving |
| **Default** | **`60s` / `300s` / `1800s`** | Uses each grade's justified ceiling |
| Aggressive | `300s` / `900s` / `3600s` | Largest saving; a traffic-path change can go unnoticed for 15 minutes |

Under the default profile, an externally deleted or replaced Flareway CNAME is a T2 change and is detected within five minutes.

## The drift sweep

A single leader-elected worker lists each enabled sweep target once per grade period and compares the result against cluster state. It filters targets by controller group before starting the target loops, and dispatches wakeup notifications over per-kind fan-out channels (`Gateway` also subscribes to `CloudflareTunnel` drift) using bounded non-blocking sends. Because channel sends are non-blocking, wakeup notifications are best-effort if a subscriber's buffer fills; the in-memory invalidation latch retains the drift marker so the affected object still closes its gate (`closed_invalidated`) on its next reconcile or periodic retry without waiting on a slow subscriber.

| Case | Meaning | Action |
|---|---|---|
| Mismatch | Both sides exist, contents differ | Invalidate the object's gate and wake its reconciler |
| Missing | Kubernetes records a remote ID that does not exist in Cloudflare | Invalidate and wake |
| Orphan | A remote object carries Flareway's ownership marker but no Kubernetes object claims it | Report only |

The sweep reports orphans and never deletes them. Deleting a remote object is destructive and stays with the owning reconciler's teardown path, which re-reads the remote before acting.

### Controller-group sweep selection

The sweep target set follows the five controller group flags:

| Group | Sweep targets |
|---|---|
| Gateway | `DNSRecord`, `CloudflareTunnel` |
| Access | `AccessApplication`, `AccessStandaloneApplication`, `AccessInfrastructureTarget`, `AccessCustomPage`, `AccessPolicy`, `AccessGroup`, `IdentityProvider`, `DevicePostureRule`, `DevicePostureIntegration`, `ServiceToken` |
| Private Network | `VirtualNetwork`, `NetworkRoute`, `HostnameRoute`, `WARPConnector` |
| Device | `DeviceProfile` |
| Organization | `ZeroTrustGatewayPolicy`, `ZeroTrustList` |

`DeviceSettings` and `ZeroTrustOrganization` are singleton APIs, so they are not sweep targets. With every group enabled, the sweep retains all 19 targets. A disabled group stops its reconcilers, contributes no sweep targets, and makes no corresponding remote list calls; its objects remain unverified until the group is re-enabled. Re-enabling it restores the reconcilers and sweep targets. Explicitly disabling every group leaves the target set empty. The sweep API budget counts enabled targets only. `--disable-sweep` remains an all-or-nothing switch for the entire sweep.

### Content confirmation

After a reconciler verifies an object against Cloudflare, it records the desired content it verified. On each pass the sweep compares every listed object against that record, as well as against its name and ownership tags:

- A match counts as a fresh verify. The object's own TTL wake-up finds the gate open and reads nothing.
- A difference is reported as a `mismatch`. The sweep invalidates the object's gate and wakes its reconciler, which re-reads Cloudflare and repairs the object (or holds, under `--drift-policy=Hold`).

A sweep confirmation keeps the gate open for two periods, so a new pass always lands before the last confirmation expires. Detection bounds for an out-of-band change on a confirmed object:

| Sweep state | Detected within |
|---|---|
| Running | The next pass: at most 1.2 × TTL plus the listing time |
| Stopped, failing, or `--disable-sweep` | 2 × TTL, when the object's own verify resumes |

Confirmation requires complete listings for all relevant scopes. For strict-contract account-wide targets, any listing failure aborts the pass and confirms nothing. DNS records (`status.dnsRecords[].zoneId` checkpoints) are judged per listed zone and never run content confirmation. For the four zone-scoped Access targets (`AccessApplication`, `AccessStandaloneApplication`, `AccessGroup`, `ServiceToken`), a pass with isolated zone failures judges and confirms objects whose target `spec.zone` scope and distinct checkpointed `status.zoneId` scope both completed listing (for `AccessGroup`, partial passes also require `Accepted=True`/`Ready=True` aligned with the current generation so inherited or interrupted zone checkpoints are withheld until scoped observation re-establishes them; other targets keep partial-pass judgement even on local conditions such as `ServiceToken` `SecretMissing`); objects touching an unlisted zone or an unverified `AccessGroup` binding remain unconfirmed and are never marked missing, falling back to their own verify (`ServiceToken` is always self-verified and never confirmed by the sweep).

Content confirmation applies only where the listing shows everything the reconciler checks:

| Kind | Confirmed by the sweep unless |
|---|---|
| `AccessApplication` | it is a `ProxyEndpoint` |
| `AccessStandaloneApplication` | it holds a one-time SaaS client secret or references un-listed `externalId` / `externalRef` dependencies |
| `AccessPolicy`, `AccessGroup` | rules reference un-listed `externalId` dependencies |
| `AccessInfrastructureTarget` | always confirmed |
| `IdentityProvider` | SCIM is enabled |
| `VirtualNetwork`, `HostnameRoute`, `ZeroTrustGatewayPolicy` | always confirmed |
| `NetworkRoute` | it uses `ipLookup` |

Every other object keeps its own verify once per TTL. `ServiceToken` is one of them: its verify also checks the credential Secret and refreshes the token before it expires.

An `AccessApplication` is checked against more than its own listed entry:

- Application listings embed each attached policy in full, so a policy deleted out of band shows up as changed content.
- Its bypass children are applications in the same listing. Each one must still match its desired content, and no other application may carry the parent's bypass marker.
- When any `AccessApplication` whose target and prior checkpointed scopes completed listing references identity providers or custom pages, the same pass also lists them. A referenced one missing from that listing is drift. If either reference listing fails, the pass aborts and confirms nothing.

Local state an `AccessApplication` depends on, such as its Gateways, data planes, and the tunnel's forwarding status, is part of the gate's desired hash. A change there runs the full pass without waiting for the sweep.

Gates stay open only while the object's live Kubernetes status is converged on the current generation (`Ready=True` or `Programmed=True`; for `CloudflareTunnel` in `dns.mode: External`, `Ready=True`, verified ownership/account identity, `DNSReady=True`, and empty `status.dnsRecords`; and for `Gateway`'s `CloudflareTunnelConfig` gate, both `ConfigApplied=True` on the tunnel's current generation and `Programmed=True` on the Gateway's current generation). Established `ServiceToken` reconciles also verify `spec.secretRef` exists in Kubernetes before opening the gate, failing with `SecretMissing` rather than masking credential deletion. Pre-gate and remote failures that demote status (including Gateway admission and `GatewayClass` config rejections, compile, snapshot, and dataplane failures on the owning writer's `CloudflareTunnelConfig` key, respecting writer identity and keeping the `CloudflareTunnel` key distinct) forget cached verifications and sweep confirmations and close the gate with `closed_unconverged`, so recovery runs immediately once dependencies return rather than waiting for TTL expiry.

Confirmations live in operator memory. After a restart or leader change, each object verifies itself once and records its content again.

## API budget and DNS zone scope

The sweep lists each enabled resource kind once per period, regardless of how many objects exist. For kinds whose listing shows everything a reconciler checks, that listing also stands in for each object's own re-verify (see [Content confirmation](#content-confirmation)), so a converged object reads nothing until the sweep reports drift on it or the sweep stops. Converged `AccessPolicy`, `AccessGroup`, `AccessStandaloneApplication`, `DevicePostureRule`, and `ZeroTrustOrganization` objects also defer remote existence checks for `externalId` / `externalRef` references until the gate closes (or `ObserveOnly`), so open-gate passes make zero Cloudflare reads even when referencing external IDs; objects with un-listed external references omit parent-only sweep confirmation and re-verify on their bounded freshness TTL instead. For sweep-confirmed objects without un-listed external dependencies, steady-state Cloudflare API traffic does not grow with their number. Every other object reads its remote once per freshness TTL.

The sweep runs on a dedicated `0.5 req/s` budget for enabled targets, separate from the `3.5 req/s` reconciler budget, so the two together stay inside Cloudflare's `4.0 req/s` account limit. It starts each enabled kind on a staggered delay so a restart does not produce a burst.

The sweep never treats a partial page as a complete list, because a partial list would make healthy objects look missing. For most kinds, a listing that fails partway through discards the whole pass.

The DNS sweep lists only the zones this installation can own records in: every zone named in the account's `spec.grants[].zones` (all zones when any grant lists `"*"`), plus every zone where a managed `CloudflareTunnel` still has a record in `status.dnsRecords`, which covers zones whose grant was revoked. The sweep never calls other zones in the account, so a token that can read DNS only in the granted zones produces `result="ok"` when everything is healthy. A zone ID in `status.dnsRecords` that is missing from the account is skipped, and its checkpoints are not judged.

DNS records and zone-scoped Access targets (`AccessApplication`, `AccessStandaloneApplication`, `AccessGroup`, and `ServiceToken`) isolate per-zone failures, because a zone in that set can still be unreadable, for example after the token was narrowed or when a DNS-scoped token lacks Zone Access permissions. When listing one zone fails with an access or server error (HTTP 403, 404, or 5xx, or a transport failure mid-pagination), the sweep drops that zone's records and continues through the remaining permitted scopes: DNS judges each `status.dnsRecords[].zoneId` checkpoint against its zone's listing (without content confirmation), while zone-scoped Access judges and confirms an object only when both its target `spec.zone` scope and any distinct checkpointed `status.zoneId` scope completed listing. A scope that could not be listed is never treated as empty, so its objects cannot be misreported as deleted. Account-scope failures on Access targets, authentication failures, rate limiting, and cancellation still abort the whole pass, as does any listing failure on the other kinds.

A DNS or zone-scoped Access pass with isolated zone failures reports `result="partial"`, never `ok`, even when every zone was denied. It preserves findings from completed scopes and logs an aggregate diagnostic naming the failed zones and their causes, and `flareway_sweep_last_success_timestamp` does not advance. Per-zone authentication, rate-limiting, pacing, and deadline failures abort the pass with `result="error"`; context cancellation aborts silently. Account-wide zone discovery and other resource kinds report the generic partial or error outcome, without partial findings or a per-zone aggregate.

## Drift policy

`--drift-policy` controls what happens once drift is detected:

- `Overwrite` (default) restores the desired state.
- `Hold` reports the drift and skips the remote write until the spec changes or the remote is repaired. Use it when an operator may have tightened something by hand during an incident and you do not want Flareway to widen it again.

## Disabling the sweep or gates

`--disable-sweep` stops the sweep worker. Freshness gates with a positive TTL keep working, and every object on a positive grade reads its remote once per TTL so out-of-band drift is detected when that TTL expires (grade-0 controllers follow their fallback intervals, such as `10s` on a programmed `Gateway`).

Setting a freshness flag to `0` stops that grade's target sweep loops (even if `--disable-sweep` is unset) and keeps its gates closed, so reconcilers read Cloudflare on every reconcile pass. Controllers with periodic drift loops (`AccessStandaloneApplication`, `ZeroTrustGatewayPolicy`, `ZeroTrustList`, `ZeroTrustOrganization`, `WARPConnector`, `DeviceSettings`, `CloudflareTunnel`, and `Gateway`) fall back to their periodic requeue intervals even when freshness is `0`; `ServiceToken` keeps its credential-expiry scheduler independently of freshness TTL; and event-driven controllers (`AccessApplication`, `AccessPolicy`, `AccessGroup`, `AccessInfrastructureTarget`, `AccessCustomPage`, `IdentityProvider`, `DevicePostureRule`, `DevicePostureIntegration`, `VirtualNetwork`, `NetworkRoute`, `HostnameRoute`, and `DeviceProfile`) return `RequeueAfter=0s` and recheck on Kubernetes watch events:

```
--freshness-authz=0 --freshness-traffic=0 --freshness-indirect=0 --freshness-display=0
```

## Metrics

| Metric | Labels | Reading |
|---|---|---|
| `flareway_gate_total` | `kind`, `decision` | `decision` is one of `open`, `closed_hash`, `closed_ttl`, `closed_invalidated`, or `closed_unconverged`. `open` counts skipped remote reads; `closed_unconverged` counts passes forced to run because live status is not yet converged on the current generation. A kind stuck at `closed_hash` means its desired hash keeps changing, usually because of an unstable spec input (the Gateway tunnel-config gate reports `kind="CloudflareTunnelConfig"`, separate from `"CloudflareTunnel"` DNS/identity sweep invalidation) |
| `flareway_drift_detected_total` | `kind`, `case` | Out-of-band changes found, by `orphan`, `missing`, `mismatch`, or `version` |
| `flareway_sweep_total` | `kind`, `result` | `ok`, `partial`, or `error` per sweep pass |
| `flareway_sweep_last_success_timestamp` | `kind` | Last pass that observed a complete listing. A stale value with rising `partial` counts means drift detection is degraded |
| `flareway_cloudflare_requests_total` | `service`, `status` | Actual API traffic, for confirming the saving |

None of these carry account, object, or namespace labels.

## Setting the flags

`--freshness-authz`, `--freshness-traffic`, `--freshness-indirect`, `--freshness-display`, `--drift-policy`, and `--disable-sweep` are controller-manager arguments. The Helm chart sets them from its `reconcile` values, and the chart defaults match the defaults on this page:

| Value | Flag | Default |
|---|---|---|
| `reconcile.driftPolicy` | `--drift-policy` | `Overwrite` |
| `reconcile.freshness.authz` | `--freshness-authz` | `60s` |
| `reconcile.freshness.traffic` | `--freshness-traffic` | `300s` |
| `reconcile.freshness.indirect` | `--freshness-indirect` | `1800s` |
| `reconcile.freshness.display` | `--freshness-display` | `0s` |
| `reconcile.disableSweep` | `--disable-sweep` | `false` |

To hold drift and shorten the traffic grade on an installed release:

```sh
helm upgrade flareway oci://ghcr.io/isac322/charts/flareway \
  --version <chart-version> \
  --namespace flareway-system \
  --reuse-values \
  --set reconcile.driftPolicy=Hold \
  --set reconcile.freshness.traffic=120s
```

The [chart README](../../charts/flareway/README.md#drift-detection-and-freshness) lists the accepted formats for each value.
