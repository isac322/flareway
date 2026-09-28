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
| T2 | `--freshness-traffic` | `300s` | `CloudflareTunnel`, DNS records, `ZeroTrustGatewayPolicy`, `ZeroTrustList`, `VirtualNetwork`, `NetworkRoute`, `HostnameRoute` |
| T3 | `--freshness-indirect` | `1800s` | `DeviceProfile`, `DeviceSettings`, `DevicePostureRule`, `DevicePostureIntegration`, `ZeroTrustOrganization`, `WARPConnector` |
| T4 | `--freshness-display` | `0` | Display-only reads. `0` means no periodic read. |

`CloudflareAccount` has no grade. Its remote calls are the resource's own liveness and authorization evidence rather than convergence reads, and they run on a ten-minute cycle.

The manager rejects a negative duration and requires `--freshness-authz` ≤ `--freshness-traffic` ≤ `--freshness-indirect` among the positive values. A grade set to `0` is on-demand and exempt from that ordering.

### Choosing a profile

| Profile | T1 / T2 / T3 | Character |
|---|---|---|
| Conservative | `30s` / `60s` / `600s` | Fastest detection; smallest saving |
| **Default** | **`60s` / `300s` / `1800s`** | Uses each grade's justified ceiling |
| Aggressive | `300s` / `900s` / `3600s` | Largest saving; a traffic-path change can go unnoticed for 15 minutes |

Under the default profile, an externally deleted or replaced Flareway CNAME is a T2 change and is detected within five minutes.

## The drift sweep

A single leader-elected worker lists each resource kind once per grade period and compares the result against cluster state. It classifies three cases:

| Case | Meaning | Action |
|---|---|---|
| Mismatch | Both sides exist, contents differ | Invalidate the object's gate and wake its reconciler |
| Missing | Kubernetes records a remote ID that does not exist in Cloudflare | Invalidate and wake |
| Orphan | A remote object carries Flareway's ownership marker but no Kubernetes object claims it | Report only |

The sweep reports orphans and never deletes them. Deleting a remote object is destructive and stays with the owning reconciler's teardown path, which re-reads the remote before acting.

### Content confirmation

After a reconciler verifies an object against Cloudflare, it records the desired content it verified. On each pass the sweep compares every listed object against that record, as well as against its name and ownership tags:

- A match counts as a fresh verify. The object's own TTL wake-up finds the gate open and reads nothing.
- A difference is reported as a `mismatch`. The sweep invalidates the object's gate and wakes its reconciler, which re-reads Cloudflare and repairs the object (or holds, under `--drift-policy=Hold`).

A sweep confirmation keeps the gate open for two periods, so a new pass always lands before the last confirmation expires. Detection bounds for an out-of-band change on a confirmed object:

| Sweep state | Detected within |
|---|---|
| Running | The next pass: at most 1.2 × TTL plus the listing time |
| Stopped, failing, or `--disable-sweep` | 2 × TTL, when the object's own verify resumes |

Only a complete listing confirms anything. A pass that fails or is partial confirms nothing, and objects fall back to their own verify.

Content confirmation applies only where the listing shows everything the reconciler checks:

| Kind | Confirmed by the sweep unless |
|---|---|
| `AccessApplication` | it is a `ProxyEndpoint` |
| `AccessStandaloneApplication` | it holds a one-time SaaS client secret |
| `AccessPolicy`, `AccessGroup`, `AccessInfrastructureTarget` | always confirmed |
| `IdentityProvider` | SCIM is enabled |
| `VirtualNetwork`, `HostnameRoute`, `ZeroTrustGatewayPolicy` | always confirmed |
| `NetworkRoute` | it uses `ipLookup` |

Every other object keeps its own verify once per TTL. `ServiceToken` is one of them: its verify also checks the credential Secret and refreshes the token before it expires.

An `AccessApplication` is checked against more than its own listed entry:

- Application listings embed each attached policy in full, so a policy deleted out of band shows up as changed content.
- Its bypass children are applications in the same listing. Each one must still match its desired content, and no other application may carry the parent's bypass marker.
- When any application references identity providers or custom pages, the same pass also lists them. A referenced one missing from that listing is drift. If either listing fails, the pass confirms nothing.

Local state an `AccessApplication` depends on, such as its Gateways, data planes, and the tunnel's forwarding status, is part of the gate's desired hash. A change there runs the full pass without waiting for the sweep.

Confirmations live in operator memory. After a restart or leader change, each object verifies itself once and records its content again.

## API budget and DNS zone scope

The sweep lists each resource kind once per period, regardless of how many objects exist. For kinds whose listing shows everything a reconciler checks, that listing also stands in for each object's own re-verify (see [Content confirmation](#content-confirmation)), so a converged object reads nothing until the sweep reports drift on it or the sweep stops. For those objects, steady-state Cloudflare API traffic does not grow with their number. Every other object reads its remote once per freshness TTL.

The sweep runs on a dedicated `0.5 req/s` budget, separate from the `3.5 req/s` reconciler budget, so the two together stay inside Cloudflare's `4.0 req/s` account limit. It starts each kind on a staggered delay so a restart does not produce a burst.

The sweep never treats a partial page as a complete list, because a partial list would make healthy objects look missing. For most kinds, a listing that fails partway through discards the whole pass.

The DNS sweep lists only the zones this installation can own records in: every zone named in the account's `spec.grants[].zones` (all zones when any grant lists `"*"`), plus every zone where a managed `CloudflareTunnel` still has a record in `status.dnsRecords`, which covers zones whose grant was revoked. The sweep never calls other zones in the account, so a token that can read DNS only in the granted zones produces `result="ok"` when everything is healthy. A zone ID in `status.dnsRecords` that is missing from the account is skipped, and its checkpoints are not judged.

DNS records are the one exception to discarding a failed listing, because a zone in that set can still be unreadable, for example after the token was narrowed. When listing one zone fails with an access or server error (HTTP 403, 404, or 5xx, or a transport failure mid-pagination), the sweep drops that zone's records, continues through the remaining zones, and still reports drift found in the zones it could read. A zone that could not be listed is never treated as empty, so its records cannot be misreported as deleted. Authentication failures, rate limiting, and cancellation still abort the whole pass, as does any listing failure on the other kinds.

A DNS pass with isolated zone failures reports `result="partial"`, never `ok`, even when every zone was denied. It preserves findings from completed zones and logs an aggregate diagnostic naming the failed zones and their causes, and `flareway_sweep_last_success_timestamp` does not advance. Per-zone authentication, rate-limiting, pacing, and deadline failures abort the pass with `result="error"`; context cancellation aborts silently. Account-wide zone discovery and other resource kinds report the generic partial or error outcome, without partial findings or a DNS zone aggregate.

## Drift policy

`--drift-policy` controls what happens once drift is detected:

- `Overwrite` (default) restores the desired state.
- `Hold` reports the drift and skips the remote write until the spec changes or the remote is repaired. Use it when an operator may have tightened something by hand during an incident and you do not want Flareway to widen it again.

## Disabling the sweep or gates

`--disable-sweep` stops the sweep worker. Freshness gates keep working, and every object reads its remote once per TTL, so out-of-band drift is detected only when that TTL expires.

Setting every freshness flag to `0` keeps every gate closed, so reconcilers read the remote on every pass:

```
--freshness-authz=0 --freshness-traffic=0 --freshness-indirect=0 --freshness-display=0
```

## Metrics

| Metric | Labels | Reading |
|---|---|---|
| `flareway_gate_total` | `kind`, `decision` | `decision="open"` counts skipped remote reads. A kind stuck at `closed_hash` means its desired hash keeps changing, usually because of an unstable spec input |
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
