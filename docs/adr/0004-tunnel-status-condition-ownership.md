# ADR 0004: One field manager for tunnel conditions

- Status: Accepted
- Date: 2026-09-23
- Issue: [#92](https://github.com/isac322/flareway/issues/92)

## Context

Two reconcilers write `CloudflareTunnel` status with server-side apply (SSA). The tunnel reconciler owns the remote tunnel data (`tunnelId`, `dnsRecords`, `clients`, `addresses`, and the identity fields) under the `flareway-tunnel` field manager. In Gateway configuration mode, the Gateway reconciler owns `configVersion`, `hostnames`, and `listeners` under `flareway-gateway`. Both reconcilers also author conditions: the Gateway reconciler reports `ConfigApplied`, and the tunnel reconciler reports `TunnelReady`, `DNSReady`, and the aggregate `Ready`.

`Ready` is a function of `TunnelReady`, `ConfigApplied`, and `DNSReady`. Independent condition commits from independent snapshots can tear: on a converged Gateway, three symptoms combine (issue #92):

- A Gateway reconcile writes `ConfigApplied=False` (reason `Pending`) partway through the pass and restores `True` at the end, so consumers such as `kubectl wait`, GitOps health checks, and alerts can observe a false negative on a healthy tunnel.
- The restored `True` takes its `lastTransitionTime` from the pass's starting snapshot, so the timestamp moves backwards.
- The tunnel reconciler derives `Ready` from a stale snapshot and commits it separately, so `(ConfigApplied=False, Ready=True)` can persist on the API server.

Each condition write also bumps `resourceVersion` and wakes both reconcilers through their tunnel watches, so a transient `False` feeds its own churn.

The design must keep `Ready` consistent with its inputs in every persisted revision, keep a converged tunnel quiet, and keep crash windows around the Cloudflare configuration push fail-closed.

## Decision

All Flareway condition types on `CloudflareTunnel` are owned by one shared SSA field manager, `flareway-tunnel-status` (`internal/controller/tunnel_conditions.go`). Both reconcilers commit conditions through one optimistic-concurrency transaction. The data fields stay with the existing managers.

### Ownership split

| Manager | Owns |
|---|---|
| `flareway-tunnel-status` | `Accepted`, `TunnelReady`, `ConfigApplied`, `DNSReady`, `PrivateListenerDegraded`, `Ready`, `CleanupBlocked`, `Conflict`, `DriftDetected` |
| `flareway-tunnel` | Tunnel-owned data: remote identity, `dnsRecords`, `clients`, `addresses` |
| `flareway-gateway` | `configVersion`, `hostnames`, `listeners` (Gateway mode only) |

Data applies omit `status.conditions`. `status.conditions` is a `+listType=map` list keyed by `type`, so an entry missing from an apply document stays untouched and unowned. The shared manager never places a non-Flareway condition type in its document, and external conditions keep their owners.

The single-writer rule for tunnel configuration (invariant G4) is separate from this split. The shared manager decides who owns Kubernetes status entries; G4 decides who writes the remote Cloudflare configuration. In Direct mode the tunnel reconciler authors `ConfigApplied` through the same transaction, and the Gateway writers refuse Direct-mode tunnels. The tunnel reconciler refuses to author `ConfigApplied` outside Direct mode.

### The conditions transaction

`patchTunnelConditions` runs each attempt in this order:

1. Read the live tunnel through the uncached API reader. The live `resourceVersion` becomes the basis for the write.
2. Check identity: the live object must match the observed UID, `metadata.generation`, and configuration mode. A mismatch aborts without writing.
3. Run the caller's guard, if any, against the live object.
4. Merge the authored deltas onto the live Flareway set. Non-authored Flareway entries are carried from the live object unchanged, including their timestamps. An authored entry whose `status` matches live keeps the live `lastTransitionTime`; a changed entry takes the caller's clock.
5. Derive `Ready` in the same document.
6. Skip the write if the merged set is semantically equal to live and the shared manager already owns every Flareway type in it.
7. Otherwise apply with `ForceOwnership` and the live `resourceVersion` pinned. A 409 Conflict restarts from step 1, up to three attempts. Remote actions are never replayed.

Callers pass only the deltas authored in this pass, never a `Ready` computed elsewhere and never entries copied from a cached read.

### Ready rule

`deriveTunnelReadyCondition` sets `Ready=True` only when `TunnelReady`, `ConfigApplied`, and `DNSReady` are all `True` in the merged document. The clamp runs on every commit, including a commit that authors nothing: a live `Ready=True` with an unmet input becomes `Ready=False` (reason `Pending`) in the same apply. A lifecycle override such as ObserveOnly's `Ready=False` wins over derivation, but no override can produce `Ready=True` while an input is unmet.

### Commit order

Every status update runs the conditions transaction before the data apply. The first commit claims ownership of the Flareway entries for the shared manager. SSA deletes fields that the applying manager owned but omitted, so a data-only apply that ran first could delete condition entries still owned solely by `flareway-tunnel` or `flareway-gateway`.

Promotions wait for their evidence. A `True` value for `Ready` or one of its inputs commits only after the status data that justifies it is durable:

- The tunnel reconciler's `patchOwnedStatus` commits conditions with promotions withheld, applies its data, then commits the withheld promotions.
- A Gateway demotion uses `patchTunnelGatewayStatus`: conditions first, then data.
- A Gateway promotion runs a conditions commit with no deltas (ownership claim and clamp), applies the data, then commits `ConfigApplied=True` through `patchTunnelGatewayConditionsValidated` with the promotion guard.

### Writer guards

The Gateway reconciler re-runs `gatewayTunnelConditionGuard` against the fresh tunnel on every attempt of both its conditions and data writes. The guard requires the live Gateway to exist with the observed UID and no `deletionTimestamp`, the tunnel's remote and owner identity to match what the pass observed, the Gateway to be the selected UID-bound owner with no drain pending, and the tunnel to be managed, verified, not remotely deleted, with a `tunnelId` and connector token Secret.

`gatewayPromotionGuard` adds the evidence check for `ConfigApplied=True`. Each domain is judged in its own units:

- the live `configVersion` still records this pass's desired version, desired hash, and remote version;
- the exact compiled xDS snapshot identity is ACKed;
- when the full gate applies, every active cloudflared Pod reports the desired Cloudflare configuration version and managed DNS is ready.

The xDS snapshot identity is a string and the Cloudflare configuration version is an int64. They are never compared with each other. If convergence evidence is lost between the gate and the commit, the pass demotes `ConfigApplied` and reports the Gateway pending. A provenance mismatch aborts without demoting, so a pass never writes to another owner's or another generation's object.

The tunnel reconciler has no ownership guard because it is the authority that sets `ownershipVerified`, `gatewayRef`, and `deletedAt`. Gating on those fields would block provisioning, ObserveOnly, conflict, and teardown writes.

### Steady state

The Gateway reconciler writes `ConfigApplied=False` before the programming gate only when the Cloudflare configuration step reports pending, drift, or a drift hold. A converged pass authors the same conditions it finds, so the conditions commits skip and the object keeps its `resourceVersion`.

### Invalidation around the configuration push

`reconcileCloudflaredConfiguration` takes the tunnel lock and reads the remote configuration. If the persisted `desiredHash` matches the compiled hash and the remote version equals the persisted desired version, the pass confirms the recorded version without a push. Otherwise, immediately before `UpdateTunnelConfiguration`, it commits `ConfigApplied=False` (reason `Applying`) through the conditions transaction. The derived `Ready` drops to `False` in the same document. The intended hash appears only in the message; `configVersion.desiredHash` keeps the hash of the last successful push until the push succeeds. After a successful push, one data apply records the provider-assigned version, hash, remote version, and `appliedAt`, and the programming gate decides promotion. A remote error demotes `ConfigApplied` before the error returns.

### Remote identity capture

`CreateTunnel` is not idempotent, and `status.tunnelId` is the only record of the created object. The tunnel reconciler commits its conditions before calling `ensureRemoteTunnel`, so the status subresource exists before any create. `persistRemoteIdentity` then records the identity with an RFC 6902 JSON Patch. The patch has one precondition, a `test` operation on `/metadata/uid`, and adds the identity fields the remote read returns — `tunnelId`, `accountId`, `name`, `tunnelType`, `configSource`, `connectorState`, `createdAt`, `deletedAt`, and `ownershipVerified` — skipping any that are absent rather than writing a JSON null. It carries no generation or `resourceVersion` precondition, so a spec edit or a concurrent status write cannot veto the capture. JSON Patch has no SSA ownership semantics, so the patch cannot delete or claim condition entries.

### Watches

The tunnel reconciler's `For(&CloudflareTunnel{})` and the Gateway reconciler's tunnel watch carry no predicate. Both reconcilers depend on status-only wakeups: the Gateway reads `tunnelId`, `ownershipVerified`, `connectorTokenSecretRef`, `deletedAt`, and `dnsRecords` from tunnel status. Churn is removed at the source by skipping unchanged writes.

## Consequences

- Every persisted revision keeps `Ready` consistent with `TunnelReady`, `ConfigApplied`, and `DNSReady`. The torn pair `(ConfigApplied=False, Ready=True)` can exist only in a writer's memory.
- A converged tunnel produces no condition changes, no `resourceVersion` bumps from conditions, and no self-inflicted watch events.
- `lastTransitionTime` moves only on a real status change.
- `ConfigApplied=False` with reason `Applying` is visible for the duration of a configuration push. Consumers see a real pending state, not a flap.
- A crash after the push and before the checkpoint leaves remote state ahead of status. The next pass sees a remote version different from its baseline and takes the drift path: the default policy re-pushes, and `DriftPolicy: Hold` reports an out-of-band change. Delivery is at least once.
- The optimistic-concurrency check covers only the `CloudflareTunnel` object. A Gateway spec change can race a tunnel commit; the Gateway watch requeues a correcting pass.
- A status update costs up to three requests (conditions, data, promotion), each retried at most three times on conflict.
- A legacy co-owner that never releases its condition entries (a deleted Gateway, or a tunnel that moved from Gateway to Direct mode) does not force a write every pass. Once the shared manager covers the set, equal content skips.

## Alternatives considered

| Alternative | Reason rejected |
|---|---|
| Fix only the Gateway's early `ConfigApplied=False` write | Stops the flap but leaves `Ready` derived by a different writer from a different snapshot, so the torn pair can still persist. |
| Keep per-writer managers and add a fresh read with a `resourceVersion` check to each | Each writer still commits its half separately. A reader between the two commits can observe a torn pair. |
| Move `Ready` to the Gateway manager | Gateway mode only. Direct mode and ObserveOnly have no Gateway writer, and `Ready`'s inputs `TunnelReady` and `DNSReady` stay with the tunnel reconciler. Switching the owner of a single entry by mode also rewrites `managedFields` on each switch. |
| One shared manager for all tunnel status | Freshness and clear-intent rules for `configVersion`, `dnsRecords`, and `clients` differ per writer. Merging them into one transaction widens every write and couples unrelated data. |
| Record the new desired hash before the push | Breaks the no-change fast path under the tunnel lock. If the push then fails, the persisted hash matches the compiled hash and later passes skip the push indefinitely. |
| Filter tunnel watches to generation changes | The Gateway and tunnel reconcilers depend on status-only events for tunnel ID assignment, ownership, credential, and DNS changes. A filter would trade churn for missed wakeups. |
| Capture remote identity through the conditions transaction | The transaction's generation and `resourceVersion` checks could veto the capture after a non-idempotent create, losing the only record of the remote tunnel. |
