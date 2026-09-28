# ADR 0005: Journal ServiceToken create intent

- Status: Accepted
- Date: 2026-09-23
- Issue: [#94](https://github.com/isac322/flareway/issues/94)

## Context

Cloudflare returns a service token's client secret only in the response to `CreateServiceToken`. Invariant G6 requires Flareway to capture such one-time credentials durably, in a controller-owned Secret, before it reports the resource Ready.

A create-then-write reconcile has a window between the remote create and the credential Secret write. If the Secret write fails in that window, for example on an API server 503, the pass returns an error with `status.tokenId` empty and no Secret (issue #94). A naive reconcile that retried `CreateServiceToken` on the next pass would have no record of the issued token (recovering the ID from an annotation on the credential Secret is impossible when the Secret does not exist), so the retry would strand the first token. Deleting the recorded `status.tokenId` would remove only what status knows, the account sweeper reports orphans without reclaiming them, and the unrecorded token would survive.

An unrecorded token is a provenance failure more than a Ready failure: the controller loses the identity of a remote object it created. The design must hold three properties:

- The controller never creates a second token for one attempt, even across a crash.
- It never adopts, rotates, or deletes a remote token whose provenance it cannot prove.
- It never drops a one-time credential it received.

## Decision

A managed fresh create records its intent in a durable journal before the remote create. Recovery resumes from the journal instead of creating blindly. The implementation is in `internal/controller/servicetoken_recovery.go`, with the entry points in `servicetoken_controller.go`.

### The journal

The journal is a Secret named `flareway-st-intent-<ServiceToken UID>`, controlled by the ServiceToken. Its keys are private to the controller package. It binds an immutable identity tuple:

- ServiceToken UID and the cluster ID (the `kube-system` Namespace UID);
- CloudflareAccount name, UID, and account ID;
- `spec.zone` as written and the resolved zone ID;
- `spec.name` and the credential destination Secret;
- a random attempt nonce (8 bytes, hex-encoded) and the attempt name derived from it.

It also records the phase (`prepared`, `dispatched`, or `retiring`), the issued token ID once known, and the ID and name of a token being retired.

Only the managed fresh-create path writes a journal. `AdoptById`, `ObserveOnly`, and an established token (with `status.tokenId` set) never create one. The controller reads the cluster ID, the journal, and the credential Secret through the uncached API reader, which `SetupWithManager` initializes. If the cluster ID is unavailable or empty, the create fails closed.

### Attempt names

Each attempt creates the remote token under a name unique to the attempt:

```text
flareway/<clusterUID>/<namespace>/<ServiceToken UID>/<spec.name>-<nonce>
```

The name is capped at 200 characters by truncating `spec.name`. The prefix up to the ServiceToken UID lets a scoped listing find every token this ServiceToken started. Recovery acts only on an exact match of the full attempt name, nonce included; a prefix match can only block. After capture, the controller renames the token to its canonical name through `UpdateServiceToken`.

### Fresh create

1. List tokens in scope. Any token whose name starts with this ServiceToken's attempt prefix, or equals the canonical name, is an untracked collision: report `Conflict` and stop.
2. Generate a nonce, add the attempt finalizer `flareway.bhyoo.com/service-token-attempt`, and create the journal in phase `prepared`. The finalizer covers the window before the journal exists.
3. Reserve the destination: create an empty Secret controlled by the ServiceToken and annotated as reserved. An existing Secret must be controlled by this ServiceToken, mutable, and accept a versioned metadata update. Otherwise report `Conflict`.
4. Persist phase `dispatched`, then call `CreateServiceToken` with the attempt name.
5. Record the issued token ID in the journal.
6. Write the credential to the destination Secret. If the returned name differs from the attempt name, write the credential anyway and report `Conflict`; the create is never repeated.
7. Align mutable fields and the canonical name, patch `status.tokenId` with `Ready=True`, then delete the journal and remove the attempt finalizer.

### Recovery

When a journal exists and `status.tokenId` is empty, recovery runs after grant authorization and before the freshness gate:

- The journal must match the live spec, account, and cluster ID. A `spec.zone` or `accountRef` edit during a pending attempt reports `Conflict`. A verified-zone status flap does not: recovery resumes under the journaled zone ID.
- A pending journal under `AdoptById` reports `Conflict`. Under `ObserveOnly`, an unresolved journal with no `status.tokenId` reports `RecoveryPending` and performs no recovery mutation.
- The controller reads the destination Secret first. A credential counts as committed only when the client ID, client secret, and token ID annotation are all non-empty. A committed credential converges without rotating or re-creating. If its token ID differs from the journaled issued ID, the controller reports `Conflict`.

Otherwise the phase decides:

| Phase | Behavior |
|---|---|
| `prepared` | Reserve the destination and re-list. Send the create only when no token collides. |
| `dispatched`, no exact match | Report `Ready=False`, reason `RecoveryPending`, and re-list after 30 seconds. No create, rotate, or delete. |
| `dispatched`, more than one exact match | Report `Conflict` without mutation. |
| `dispatched`, one exact match, account scope | Record its ID, then `RotateServiceToken` to obtain a fresh credential, capture it, and converge. A failed rotate stays journaled for retry; there is no delete fallback. |
| `dispatched`, one exact match, zone scope | Zone-scoped tokens cannot rotate. Record the token as retiring and move to `retiring`. |
| `retiring` | Delete the retiring token and report `RecoveryPending`. Once `GetServiceToken` returns 404 and the listing no longer shows it, draw a new nonce and return to `prepared`. |

A journal that remains after `status.tokenId` is recorded only needs removal: the controller deletes it and the attempt finalizer, and never uses it to resume or rotate.

### Deletion and lifecycle

With `deletionPolicy: Delete` on a managed token, deletion removes the recorded `status.tokenId`, then removes any token recorded by a pending journal, using the journaled account and zone binding. If the attempt finalizer is present, the journal is gone, and `status.tokenId` is empty, the controller lists tokens in scope. It blocks if any name starts with this ServiceToken's attempt prefix, because it cannot prove which attempt created that token, and otherwise releases the finalizer without a remote mutation. Any failure reports `CleanupBlocked` and keeps the finalizer. `deletionPolicy: Orphan` keeps remote tokens. ObserveOnly never mutates remote tokens, credentials, or journals.

An established token whose credential Secret disappears reports `SecretMissing`. The controller never rotates or re-creates it on its own; rotation requires an explicit `spec.rotation.requestedAt`.

## Consequences

- A failed or interrupted credential write leaves a journal that names the issued token, so the retry recovers that token instead of creating another. The credential the controller finally captures belongs to the token recorded in status.
- A one-time credential the controller receives is written to the destination Secret even when the provider returns a divergent name.
- A `dispatched` attempt whose token never becomes visible stays `RecoveryPending` and re-lists every 30 seconds. The controller cannot tell a lost create from a slow listing, so it refuses to guess. This non-convergence is deliberate.
- Each pending create adds one Secret and one finalizer. Both are removed after status records the token.
- Until capture completes, the remote token carries the attempt name, which includes the cluster and ServiceToken UIDs.
- Provenance rests on the ownership-verified journal and the unguessable nonce. Remote service tokens have no tags or comment field to carry stronger provenance.
- A cluster restored from a clone with the same `kube-system` UID and journals, sharing one Cloudflare account, cannot be told apart from the original. If the journal, the ServiceToken, and the remote token's provenance are all lost, the design fails closed on what remains; it cannot recover what no record describes.

## Alternatives considered

| Alternative | Reason rejected |
|---|---|
| Record `status.tokenId` right after the create | Moves the window without closing it. A failed status write strands the token exactly as a failed Secret write does. |
| Delete the token in the same reconcile when the Secret write fails | The rollback lives in memory. A crash between the failed write and the rollback strands the token. |
| Adopt a remote token by name on retry | A name cannot prove provenance. It can pick a duplicate, a token from another cluster, or a token in another scope, and it cannot recover the one-time secret. Violates G2 and G3. |
| Redesign the Accepted and Ready condition API for recovery states | Existing condition reasons (`RecoveryPending`, `Conflict`, `CleanupBlocked`, `SecretMissing`) express the recovery states; a redesigned condition API adds surface without adding information. |
| Sign attempt names with an HMAC against forgery | Speculative. A forged name still has to match the full name with a random nonce. |
| Match attempts by prefix alone | Weakens provenance. Any token under the prefix could qualify for rotation or deletion; exact attempt-name matching narrows mutation to the recorded attempt. |
