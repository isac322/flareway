# Controller lifecycle

Reconcile, status, finalizer, requeue, and drift patterns used across
`internal/controller/`. Apply `rule://flareway-invariants`; ownership,
authorization, and credential rules live in `skill://flareway-security`.

## Reconcile skeleton

Every reconciler follows the same shape (see
`internal/controller/cloudflaretunnel_controller.go`):

1. `Get` the object; `client.IgnoreNotFound` on miss. Never error on a
   deleted-from-cache object.
2. `DeletionTimestamp` set → `reconcileDelete`; the finalizer gates removal.
3. Finalizer absent → add it with a `MergeFrom` patch and return; the update
   re-triggers reconcile.
4. Otherwise `reconcileActive`.

Requeue contract:

- `ctrl.Result{RequeueAfter: …}` polls remote state that has no watch
  (Cloudflare API objects, dataplane drain, connection eviction).
- Returning a non-nil error requeues with backoff **and** is reserved for
  real failures; expected waiting states patch status and requeue instead.
- `ctrl.Result{}` means "done until a watch fires". `SetupWithManager`
  registers field-index mappers (`mapXToY`) for every dependency that can
  change the outcome — Gateways, Secrets, Namespaces, routes, dataplane
  Deployments. Prefer a watch over a poll when the dependency is a
  Kubernetes object.

## Status write pattern

Conditions are built with `internal/gatewayapi/status`:

- `NewCondition(type, status, reason, message, generation, now)` — always
  pass the object's `Generation` as `observedGeneration` and one shared
  `now` per reconcile so a single pass produces deterministic timestamps.
- `SetCondition`/`MergeConditions` update by type; `LastTransitionTime`
  moves only when `Status` flips, and stale-generation updates are ignored.
- `ConditionTrue`/`ConditionFalse`/`ConditionUnknown` gate downstream logic.

Status is patched with server-side apply under a dedicated field manager
(`flareway-tunnel`, `flareway-gateway`), never `Update` on the whole object.
`patchOwnedStatus` converts the owned status struct to unstructured, deletes
fields owned by the other writer, normalizes empty lists to `[]` (teardown
needs explicit empties; `null` fails the non-nullable schema), and applies
with `ForceOwnership`.

## CloudflareTunnel status split

Two controllers share `CloudflareTunnel.status`. Know the boundary before
assuming a field is stale:

| Field manager | Owns |
|---|---|
| `flareway-tunnel` (tunnel reconciler) | `tunnelId`, `accountId`, `name`, `tunnelType`, `configSource`, `connectorState`, timestamps, `ownershipVerified`, `observedGeneration`, token Secret refs, `clients`, `addresses`, `dnsRecords`, `gatewayRef`/`gatewayUid`, `orphanedTunnelId`, conditions `Accepted`/`TunnelReady`/`DNSReady`/`Ready`/`CleanupBlocked`/`Conflict` (+ `ConfigApplied` in Direct mode only) |
| `flareway-gateway` (Gateway reconciler) | `configVersion.desired`/`desiredHash`/`applied`, `hostnames`, `listeners`, conditions `ConfigApplied` and `PrivateListenerDegraded` in Gateway mode |

In Gateway mode the tunnel reconciler still writes `configVersion.remote`
and `createdAt` (observed remote version) but strips the gateway-owned keys
from its apply. `Ready` is computed from `TunnelReady && ConfigApplied &&
DNSReady`, reading `ConfigApplied` from the *stored* status in Gateway mode
because the gateway controller owns it.

## Ownership: selectLiveTunnelGateway

`selectLiveTunnelGateway` is the single authority both reconcilers use:

- Only live (non-deleting) Gateways that claim the tunnel compete — via
  `spec.infrastructure.parametersRef` to the `CloudflareTunnel`, or an
  implicit same-name controlled-by claim.
- If `status.gatewayRef`+`gatewayUid` match a live claimant, that Gateway
  stays owner (sticky, UID-bound). Extra claimants are reported and surface
  as `Conflict=True`/`MultipleGateways`.
- If the recorded owner is gone, no successor is selected until the recorded
  owner's dataplane Deployment has scaled to zero and its Pods are gone —
  `waitingForDrain` → `Accepted=False`/`WaitingForOwnerDrain`.
- Otherwise the oldest claimant (creation time, then name) wins.

Before any Gateway-mode write, `validateGatewayTunnelWriter` re-fetches both
objects and requires: live Gateway with the same UID, the tunnel's recorded
identity matching, `managementPolicy != ObserveOnly`, no `status.deletedAt`,
`ownershipVerified`, a `tunnelId`, and a connector token Secret ref. A
soft-deleted remote tunnel (`status.deletedAt` set) blocks xDS publish,
connector scale-up, addresses, private routes, and further config writes.

## Adoption and drift

`ensureRemoteTunnel` decides create/adopt/observe:

- `ObserveOnly` requires `tunnel.externalRef.tunnelId`; it never writes, and
  `adoption.expect.name` (when set) must match the remote name.
- `Managed` with a `status.tunnelId` that is not `ownershipVerified` refuses
  to proceed unless `adoption.mode: AdoptById` plus matching `externalRef`
  and a non-empty `adoption.expect.name` — an observed ID is not ownership.
- `Managed` + `externalRef` adopts by ID only with the same explicit
  contract; the remote name must equal `adoption.expect.name`.
- A verified managed tunnel is re-fetched by `status.tunnelId`; a name drift
  is corrected with `UpdateTunnelName` to the desired name
  (`spec.tunnel.name` or `<clusterID>-<ns>-<name>`).
- Every remote object is revalidated (account ID, not soft-deleted) before
  use; failures surface as `Conflict`/`Accepted=False`, not retries.

Config drift (both modes): the remote configuration is read under
`WithTunnelLock`. If `desiredHash` matches the freshly compiled hash and the
remote version equals `configVersion.desired`, no write happens. If the
remote version differs from the recorded baseline (`applied`, else
`desired`), the tunnel reports `Conflict=True`/`ConfigurationChanged`; the
Gateway writer additionally emits an `OutOfBandChange` warning Event and
overwrites with the desired config. Never bump versions or clear the
condition manually — fix the foreign writer.

## DNS lifecycle

Managed DNS records are proxied CNAMEs to `<tunnel-id>.cfargotunnel.com`
with an ownership comment derived from cluster ID, namespace, and owner name
(the Gateway name in Gateway mode, the tunnel name in Direct mode).
`ensureDNS` creates/updates only records whose comment proves Flareway
ownership; a foreign comment is a `Conflict`/`DNSOwnership`, never an
overwrite. `dns.mode: External` or zero public hostnames removes managed
records and reports `DNSReady=True` (`External`/`NotApplicable`). Deletion
revalidates each record's status identity before removing it.

## Finalizer and teardown order

`flareway.bhyoo.com/tunnel` finalizer, `flareway.bhyoo.com/teardown`
annotation. `reconcileDelete` is strictly ordered and fail-closed:

1. Stamp the teardown annotation (active reconcile strips it if the object
   is not deleting) so the Gateway controller starts blocking.
2. Wait for the recorded Gateway UID to mark every `status.hostnames` entry
   `Blocked` — only when a live recorded owner exists and the tunnel is
   `Managed` with `ownershipVerified`. The 30s mark only changes the message;
   teardown keeps waiting and never treats the timeout as success. With no
   live owner, under `ObserveOnly`, or when ownership is unverified this wait
   does not apply and teardown proceeds to the steps below.
3. Remove managed DNS records — only under verified management
   (`managementPolicy != ObserveOnly` and `ownershipVerified`). Each record's
   status identity is revalidated against the current owner identity, or the
   checkpointed `OwnershipComment` when the owner is gone; a mismatch is a
   `DNSOwnership` conflict, never a delete.
4. Scale the recorded Gateway's dataplane to zero and wait for Pod drain.
5. Wait for `AccessApplication` cleanup (target-not-found, then delete per
   each app's own policy).
6. Refuse while `NetworkRoute`/`HostnameRoute` still reference the tunnel —
   `CleanupBlocked`/`DependenciesRemain`.
7. `deletionPolicy: Orphan`, `ObserveOnly`, or unverified ownership → record
   `orphanedTunnelId`, keep the remote tunnel.
8. Otherwise evict connections, poll until the edge reports zero
   connections, then delete the remote tunnel (cascade).
9. Remove the finalizer under `retry.RetryOnConflict` with a fresh `Get`.

Every waiting step patches `CleanupBlocked=True` with the stage in the
message and requeues. Never strip the finalizer to unblock a delete — that
leaks remote resources and can expose traffic.

## Events and observability

`observability.EmitConditionTransitions` emits warning Events only on
transitions into `Conflict`, `CleanupBlocked`, or `SecurityBlocked`, with
fixed sanitized messages — condition messages may carry upstream detail and
are never copied into Events. `observability.Default.SetConfigVersions`
exports desired/applied config versions per Gateway for the
`flareway_config_version` metric.
