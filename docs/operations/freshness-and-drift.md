# Freshness, drift detection, and Cloudflare API budget

Flareway reconcilers used to read Cloudflare on every pass. That cost grew with
the number of objects and the number of references each object carried, and it
saturated the Cloudflare account rate limit long before the cluster itself was
large.

Reconcilers now skip remote reads for objects that are already converged, and a
single periodic sweep watches the whole account for out-of-band changes. This
page describes what that changes for an operator, what it costs, and how to tune
or disable it.

## What you gain

Steady-state Cloudflare API traffic no longer scales with object count. A
converged object reads nothing until its freshness TTL expires or the sweep
reports drift on it. The sweep itself lists once per resource kind per period,
regardless of how many objects exist.

## What you give up

One thing: **out-of-band changes are detected after a delay instead of within
seconds.**

An out-of-band change is any edit made outside Flareway — the Cloudflare
dashboard, Terraform, another operator, or a person. Changes made through
Kubernetes are unaffected: they bump the object's generation, which closes the
gate immediately.

Nothing else changes. Conditions, events, ownership rules, and every
fail-closed behaviour are identical.

### What `status.appliedAt` means

`status.appliedAt` records when `status.appliedHash` was last written, so it
changes only when the desired state changes. On a `CloudflareTunnel`,
`status.configVersion.appliedAt` changes only when a configuration is written
to Cloudflare. A re-verify that finds Cloudflare already matching does not
touch status, so a converged object produces no status writes and wakes no
other controllers.

The time of that last re-verify is kept in operator memory. After a restart
or leader change it is gone, and each object's first pass reads Cloudflare
again unless its hash was recorded within the last TTL.

References from an `AccessApplication` to Cloudflare objects it does not own
(`externalRef` policies, external identity providers and custom pages, and
`ObserveOnly` policies and identity providers) are checked on the same
schedule: only on passes that go to Cloudflare anyway. A deleted reference is
found within the TTL, and the application stops being `Programmed`.

## Freshness grades

Every Cloudflare-backed kind carries a grade chosen by how directly a stale
judgement affects a security or traffic outcome. The canonical table lives in
`internal/freshness/grades.go`; both the reconciler gate and the sweep read it,
so a kind's read TTL and its drift-detection period can never disagree.

| Grade | Flag | Default | Kinds |
|---|---|---|---|
| T0 | — | always fresh | Reads before destructive writes, ownership and adoption claims, reads inside the tunnel configuration lock, and all `ObserveOnly` observation. Never gated, not tunable. |
| T1 | `--freshness-authz` | `60s` | `AccessApplication`, `AccessStandaloneApplication`, `AccessPolicy`, `AccessGroup`, `AccessCustomPage`, `AccessInfrastructureTarget`, `ServiceToken`, `IdentityProvider` |
| T2 | `--freshness-traffic` | `300s` | `CloudflareTunnel`, DNS records, `ZeroTrustGatewayPolicy`, `ZeroTrustList`, `VirtualNetwork`, `NetworkRoute`, `HostnameRoute` |
| T3 | `--freshness-indirect` | `1800s` | `DeviceProfile`, `DeviceSettings`, `DevicePostureRule`, `DevicePostureIntegration`, `ZeroTrustOrganization`, `WARPConnector` |
| T4 | `--freshness-display` | `0` | Display-only reads. `0` means no periodic read. |

`CloudflareAccount` is deliberately absent. Its remote calls are the resource's
own liveness and authorization evidence, not convergence reads, and they already
run on a ten-minute cycle.

The manager rejects a negative duration, and requires
`--freshness-authz` ≤ `--freshness-traffic` ≤ `--freshness-indirect` among the
positive values. A grade set to `0` is treated as on-demand and is exempt from
that ordering.

### Choosing a profile

| Profile | T1 / T2 / T3 | Character |
|---|---|---|
| Conservative | `30s` / `60s` / `600s` | Closest to the pre-gate detection speed; saves the least |
| **Default** | **`60s` / `300s` / `1800s`** | Uses each grade's justified ceiling |
| Aggressive | `300s` / `900s` / `3600s` | Largest saving; a traffic-path change can go unnoticed for 15 minutes |

A reference point for judging the delay: the incident that motivated this work
was three Flareway CNAMEs deleted externally and replaced with records owned by
something else. That is a T2 change, detected within five minutes under the
default profile. The pre-gate operator detected it in two seconds and then
stayed stuck for nine hours, because what actually determined the damage was the
recovery path, not the detection speed.

## The drift sweep

A single leader-elected worker lists each resource kind once per grade period
and compares the result against cluster state. It classifies three cases:

| Case | Meaning | Action |
|---|---|---|
| Mismatch | Both sides exist, contents differ | Invalidate the object's gate and wake its reconciler |
| Missing | Kubernetes records a remote ID that no longer exists | Invalidate and wake |
| Orphan | A remote object carries our ownership marker but no Kubernetes object claims it | Report only |

Orphans are reported, never deleted. Deleting a remote object is destructive and
stays with the owning reconciler's teardown path, which re-reads the remote
fresh before acting.

The sweep runs on a dedicated `0.5 req/s` budget, separate from the `3.5 req/s`
reconciler budget, so the two together stay inside Cloudflare's `4.0 req/s`
account limit. It starts each kind on a staggered delay so a restart does not
produce a burst.

If a listing fails partway through, the sweep never treats a partial page as a
complete list — a partial list would make healthy objects look missing. For
most kinds the pass is discarded entirely.

The DNS sweep lists only the zones this installation can own records in: every
zone named in the account's `spec.grants[].zones` (all zones when any grant
lists `"*"`), plus every zone where a managed `CloudflareTunnel` still has a
record in `status.dnsRecords`, which covers zones whose grant was later
revoked. Other zones in the account are never called, so a token that can read
DNS only in the granted zones produces `result="ok"` when everything is
healthy. A zone ID in `status.dnsRecords` that is no longer in the account is
skipped, and its checkpoints are not judged.

DNS records are also the one exception to discarding a failed listing, because
a zone in that set can still be unreadable, for example after the token was
narrowed. When listing one zone fails with an access or server error
(HTTP 403, 404, or 5xx, or a transport failure mid-pagination), the sweep drops
that zone's records, continues through the remaining zones, and still reports
drift found in the zones it could read. A zone that could not be listed is
never treated as empty, so its records cannot be misreported as deleted.
Authentication failures, rate limiting, and cancellation still abort the whole
pass, as does any listing failure on the other kinds.

A DNS pass with isolated zone failures is reported as `result="partial"`,
never `ok`, even when every zone was denied. It preserves findings from
completed zones and logs an aggregate diagnostic naming the failed zones
and their causes. `flareway_sweep_last_success_timestamp` does not advance.
Per-zone authentication, rate-limiting, pacing, and deadline failures abort
the pass with `result="error"`; context cancellation aborts silently.
Account-wide zone discovery and other resource kinds retain their existing
generic partial or error outcomes, without partial findings or a DNS zone
aggregate.

## Rolling back

`--disable-sweep` stops the sweep worker. Freshness gates keep working, so
out-of-band drift is then detected only when a TTL expires. To return fully to
the previous behaviour, set every freshness flag to `0`:

```
--freshness-authz=0 --freshness-traffic=0 --freshness-indirect=0 --freshness-display=0
```

A zero TTL keeps every gate closed, so reconcilers read the remote on each pass
exactly as they did before.

## Drift policy

`--drift-policy` controls what happens once drift is detected:

- `Overwrite` (default) restores the desired state, matching previous behaviour.
- `Hold` reports the drift and skips the remote write until the spec changes or
  the remote is repaired. Use this when an operator may have tightened something
  by hand during an incident and you do not want Flareway to widen it again.

## Observing it

| Metric | Labels | Reading |
|---|---|---|
| `flareway_gate_total` | `kind`, `decision` | `decision="open"` counts skipped remote reads. A kind stuck at `closed_hash` means its desired hash keeps changing — usually an unstable spec input |
| `flareway_drift_detected_total` | `kind`, `case` | Out-of-band changes found, by `orphan`, `missing`, `mismatch`, or `version` |
| `flareway_sweep_total` | `kind`, `result` | `ok`, `partial`, or `error` per sweep pass |
| `flareway_sweep_last_success_timestamp` | `kind` | Last pass that observed a complete listing. A stale value with rising `partial` counts means drift detection is degraded |
| `flareway_cloudflare_requests_total` | `service`, `status` | Actual API traffic, for confirming the saving |

None of these carry account, object, or namespace labels.
