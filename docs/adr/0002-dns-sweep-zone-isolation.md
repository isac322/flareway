# ADR 0002: Isolate DNS sweep failures per zone

- Status: Accepted
- Date: 2026-09-22
- Issue: [#93](https://github.com/isac322/flareway/issues/93)

## Context

The account sweeper lists each Cloudflare resource kind once per period and compares the listing with local state to find drift: records that are missing, mismatched, or orphaned. See [Freshness and drift](../operations/freshness-and-drift.md) for the operator view.

For every kind the sweep follows one fail-closed rule. A listing that fails partway is never judged, because an incomplete list would make healthy objects look missing. A definitive client rejection (HTTP 4xx) records `result="error"`, and any other failure records `result="partial"`. Either way the pass dispatches nothing.

DNS records differ from the other kinds because they live in zones. The DNS target lists records zone by zone with one `ListDNSRecordsByComment` call per zone and judges them against the `status.dnsRecords` checkpoints of managed `CloudflareTunnel` objects (see the [API reference](../reference/api.md)). A Cloudflare API token can hold DNS read permission for some zones and not others, so a zone can return HTTP 403 while the rest of the account lists normally.

Under the account-wide rule, one denied zone ends the whole DNS pass (issue #93). The records already collected from healthy zones are thrown away, the zones after it are never listed, and drift in the zones the token can read goes undetected on every pass. The outcome does not depend on where the denied zone sits in the list. The guard that skips checkpoints in unlisted zones never runs, because the pass stops before judgement.

A DNS listing failure needed a narrower scope than a whole pass. The decision also had to keep two properties:

- No false missing verdicts. A zone that did not list must never make its checkpointed records look absent.
- No hidden degradation. A pass that could not read every zone must not report `ok` or advance the last-success timestamp.

## Decision

The DNS target isolates listing failures per zone and returns a typed scoped partial. Every other sweep target keeps the strict account-wide contract.

### Zone scope

A DNS pass lists only the zones this installation can own records in (`dnsScanZones` in `internal/sweep/targets_dns.go`):

- zones named by any `CloudflareAccount` grant, matched with the same rule the controller applies before a DNS write, so a `"*"` grant covers the whole zone inventory;
- zones holding a checkpoint of a tunnel the pass judges, which keeps a zone in scope after its grant is revoked so its records still get drift detection and cleanup.

Zones missing from the account's zone inventory are never listed. The sweep reads the account and the tunnel list from Kubernetes before any Cloudflare call, so a failed Kubernetes read aborts the pass with `result="error"`.

### Per-zone failure classification

`zoneFailureIsolatable` decides whether a failed zone listing can be isolated. The allowlist is exact:

| Failure | Handling |
|---|---|
| HTTP 403, HTTP 404 | Isolated to the zone |
| HTTP 5xx | Isolated to the zone |
| Error with no HTTP status (transport failure, including a failure mid-pagination) | Isolated to the zone |
| Context canceled or deadline exceeded | Terminal |
| HTTP 429 | Terminal |
| HTTP 401 | Terminal |
| Any other 4xx (400, 405, 409, 422, ...) | Terminal |
| Client-side rate limiter wait failure (`ErrRateLimitWait`) | Terminal |

HTTP 429 is account-level throttling, and continuing to the next zone would make it worse. HTTP 401 is treated as authentication uncertainty and aborts the pass conservatively; it is not taken as proof that the token is invalid everywhere. Other 4xx responses point to a malformed request or a conflict that would repeat in every zone.

A failure in the client-side rate limiter is global to the account. The Cloudflare client wraps it with the `ErrRateLimitWait` sentinel (`internal/cloudflare/client.go`), and the classifier checks that sentinel before the no-status branch. Without it, the limiter's own error carries no HTTP status and no context sentinel and would look like a zone-local transport failure. When the sweeper paces calls itself, a failed wait before a zone listing also aborts the pass.

The pagination adapter returns no records when any page fails, so the sweeper never judges a partial page.

### What an isolated failure does

For each isolatable failure the pass:

1. discards any records from that zone;
2. leaves the zone out of `listedZones`, so checkpoints in that zone get no judgement (no missing, no mismatch);
3. records a `zoneFailure` holding the zone ID and the original error;
4. continues with the next zone.

The set of claimed record IDs stays account-wide. A record in a healthy zone whose checkpoint names a failed zone is still claimed, so it never becomes a false orphan.

After the loop, drift items judged against listed zones are returned together with a `*scopedListingError` that aggregates the zone failures in discovery order. A terminal failure returns no items and the raw error.

### Typed scoped partial

All targets share the `SweepFunc` signature, `func(ctx, *AccountSweeper) ([]DriftItem, error)`. The DNS target expresses the scoped partial through the error type:

- `zoneFailure` formats as `zone <id>: <cause>` and unwraps to the cause.
- `scopedListingError` formats as `scoped listing incomplete: N zone failure(s); ...`. Its `Is` method matches the generic `errIncompleteListing` sentinel, and `Unwrap() []error` exposes each `zoneFailure`, so `errors.Is` and `errors.As` reach both the zone IDs and the original causes.

Only a `*scopedListingError` may accompany items that the caller dispatches. Items returned with any other error are discarded.

### Result mapping

`RunTargetOnce` in `internal/sweep/account_sweeper.go` checks cases in this order. The scoped case must come before the generic incomplete-listing case, because `scopedListingError` also matches that sentinel and the generic branch would discard the safe items.

| SweepFunc outcome | Returned | `flareway_sweep_total` result |
|---|---|---|
| Error matching `context.Canceled` | nil items, error | none recorded |
| `*scopedListingError` | safe items, aggregate error | `partial` |
| Error matching `errIncompleteListing` | nil items, nil error | `partial` |
| Any other error, including `context.DeadlineExceeded` | nil items, error | `error` |
| nil items, nil error | nil items, nil error | `partial` |
| Items, nil error | items | `ok` |

Only the `ok` case advances `flareway_sweep_last_success_timestamp`. A scoped partial leaves it stale even when every zone was denied.

The sweep loop logs a scoped partial at Info level, `target sweep partial: scoped listing incomplete (fail-closed for unlisted scopes)`, with the aggregate error text, and then dispatches the safe items through the normal drift handling (invalidation and reconciler wakeup). A zone denied on every pass therefore does not produce a stream of Error logs. Other errors log `target sweep failed` at Error level.

### Account-level calls

Account-wide calls keep the generic contract. A failed zone inventory call (`ListZones`) goes through `listFailure`: a 4xx records `result="error"`, while a 5xx or transport failure records a generic partial with no items. The other sweep targets classify their listing failures with the same `listFailure`.

## Consequences

- A token scoped to fewer zones than the account holds does not stop drift detection in the zones it can read. Missing, mismatched, and orphaned records there are found and dispatched every pass.
- A denied zone never produces a false missing verdict, and a record claimed by a checkpoint in a failed zone never produces a false orphan.
- Operators see degradation through metrics: a stale `flareway_sweep_last_success_timestamp` with rising `result="partial"` counts for the DNS kind. The Info log names each failed zone and its cause.
- A DNS pass with a zone failure reports `partial`, not `error`. Alerts for DNS access problems watch `result="partial"` and last-success staleness.
- While a zone stays unreadable, records in it get no drift detection and no orphan cleanup. The pass stays partial until the token can read the zone again or the zone leaves scope.
- The sweep package carries a second partial contract. It is confined to the DNS target and enforced by the ordering in `RunTargetOnce`.

## Alternatives considered

| Alternative | Reason rejected |
|---|---|
| List only zones that hold a checkpoint | Loses account-wide orphan discovery in granted zones that have no checkpoint yet. The adopted zone scope (grants plus checkpoint zones) keeps orphan discovery in every zone Flareway can write to and skips zones it could never have written. |
| Keep aborting and add a debounce or wider reconcile predicate | The pass would still discard every finding. Suppressing the failure hides it instead of isolating it. |
| Require a token with DNS read on every zone in the account | Contradicts least-privilege tokens and the per-zone grant model. Read access alone does not show provisioning intent. |
| Refactor the Access sweeper to the same per-scope model | Out of scope. Other targets keep the strict contract; extending it needs its own decision. |
| Extend the public API, metrics labels, or `SweepFunc` signature | Unnecessary. A private typed error carries the scoped result with the smallest surface change. |
| Signal a zone failure with the plain `errIncompleteListing` sentinel | The sentinel carries no zone ID or cause, and the generic partial path drops the safe items. |
| Label a scoped partial `result="error"` | A single-zone account would label every denied pass as an error, and the label could not separate "listing incomplete" from "request rejected". |
| Treat HTTP 429 or 401 as zone-local | 429 is account-wide throttling and 401 signals authentication uncertainty. Continuing would worsen throttling or keep calling with a doubtful credential. |
| Isolate every 4xx | Request-shape errors repeat in every zone; isolating them would turn a defect into a permanent partial. |
