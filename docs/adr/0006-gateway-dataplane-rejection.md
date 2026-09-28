# ADR 0006: Report dataplane apply rejections

- Status: Accepted
- Date: 2026-09-23
- Issue: [#105](https://github.com/isac322/flareway/issues/105)
- Pull request: [#107](https://github.com/isac322/flareway/pull/107)

## Context

For each Gateway, the Gateway reconciler creates and applies the owned dataplane objects (Deployment, Services, ConfigMaps, and related objects) in a loop, with server-side apply under the `flareway-gateway` field manager. The desired objects depend on the Gateway spec and on the referenced `GatewayClassConfig`.

`GatewayClassConfig` accepts values that Kubernetes admission can still reject. A `nodeSelector` key such as `bad key!` passes the CRD schema, but the API server rejects the resulting Deployment as `Invalid`. Admission webhooks, Pod Security, quotas, RBAC, and immutable-field rules can reject a mutation in the same way.

Such a rejection can leave the Gateway claiming `Programmed=True` with no Event (issue #105). Three behaviors combine:

1. Reconcile persists the Gateway's pre-reconcile status before the owned-object loop, so a stored `Programmed=True` is written back unchanged.
2. `prepareConditions` demotes `Programmed` to `Unknown` only when its `observedGeneration` differs from the Gateway generation. A `GatewayClassConfig` edit does not change the Gateway generation, so the stale `True` survives.
3. The loop returns the mutation error directly. Nothing between the failed mutation and the error return records the rejection.

The error still reaches controller-runtime, so the object is retried and the existing Deployment and Services keep serving. The risk is truthfulness: a Gateway can report `Programmed=True` at the current generation indefinitely while Kubernetes rejects its desired dataplane.

The response has to separate a durable rejection from ordinary retry noise. Transient API errors and observation failures must not flap `Programmed`. Status and Events must not echo raw API error payloads, which can carry webhook text or other sensitive detail.

## Decision

A Kubernetes rejection of a Gateway-owned dataplane mutation sets the Gateway and every listener to `Programmed=False` with reason `Invalid`, then emits one Warning Event. The rejection does not tear down traffic.

### Classification at the mutation boundary

`rejectDataplaneMutation` in `internal/controller/gateway_controller.go` wraps an error in a private `dataplaneRejectionError` when an exact `apierrors` predicate matches:

| API error | Canonical reason |
|---|---|
| `IsInvalid` | `Invalid` |
| `IsForbidden` | `Forbidden` |
| `IsBadRequest` | `BadRequest` |

Every other error passes through unchanged. The wrapper stores the canonical `metav1.StatusReason` chosen at wrap time, and `Unwrap` returns the original error so `apierrors` predicates keep working on it.

Only mutation calls are wrapped:

- the initial `Create` of a missing object, except `AlreadyExists`;
- the blocking `managedFields` migration on the update path;
- the Service listener-port replacement patch;
- the final server-side apply.

Observation calls are never wrapped: the initial `Get`, the re-read after a create collision, and the re-read after port replacement. A `Forbidden` on a `Get` is an RBAC or cache fault, not a rejected spec, and stays a plain retry. An object controlled by a different owner produces a plain error and is never mutated. The `managedFields` migration that follows a successful `Create` is best-effort: a failure is logged and retried on the next reconcile, and it never counts as a rejection.

### Reporting

When the owned-object loop sees the marker (`isDataplaneRejection`), `reportDataplaneRejection`:

1. Builds the message `Kubernetes rejected the dataplane <Kind> <namespace>/<name>: <reason>` from the object's kind and key and the canonical reason. The raw API error text never enters status or Events.
2. Sets `Programmed=False`, reason `Invalid`, at the current Gateway generation on the Gateway and on every listener.
3. Persists the Gateway status.
4. After a successful write, emits a Warning Event with reason `DataplaneApplyRejected`, only if the persisted Gateway `Programmed` status, reason, or message changed.
5. Returns the original rejection so controller-runtime retries with backoff.

If the status write fails, the status error is joined onto the rejection with `errors.Join`, so a retry can persist status and both causes stay visible. The Event is emitted only after status persists, so no Event describes a rejection that status never recorded. An identical retry keeps `lastTransitionTime` and emits nothing; a different rejected object or reason changes the message and emits again.

### What the rejection leaves alone

The rejection path deletes nothing and scales nothing down. Existing Deployments and Services keep serving, and the Gateway's addresses, `Accepted` condition, and other conditions stay as they were. The rejection changes what the Gateway reports; traffic on the existing dataplane continues.

### Recovery

No special path clears the rejection. After the operator corrects the configuration, the mutation succeeds and the ordinary convergence gates (Deployment availability and xDS ACK in conformance mode, or the Cloudflare programming gate in Cloudflare mode) set `Programmed=True` again. The Gateway generation does not need to change.

### Listener Service retraction

In Cloudflare mode, deleting an unused listener Service goes through the same classifier. A rejected delete emits a `DataplaneApplyRejected` Warning Event and logs the canonical reason, but changes no status and returns no error. The unused Service is not part of the programmed dataplane.

## Consequences

- A Gateway whose desired dataplane Kubernetes rejects reports `Programmed=False` at the current generation, even when the Gateway generation never changed.
- Operators get one Warning Event per distinct rejection that names the object kind, key, and canonical API reason. Retries do not spam Events.
- Conflicts, timeouts, `TooManyRequests`, `ServiceUnavailable`, and non-API errors leave `Programmed` untouched and retry, so an ordinary retry never flaps the condition.
- Status and Events carry only the canonical reason. The full API error, including any webhook text, stays in the error the reconcile returns.
- The xDS snapshot is published before the owned-object loop, so Envoy can receive new route configuration even when a Deployment change is rejected. The rejection concerns the Kubernetes objects, not the route set.
- `Programmed=False` stays until the owned-object loop completes. A persistent rejection keeps the Gateway unprogrammed with a reason that names the rejected object.

## Alternatives considered

| Alternative | Reason rejected |
|---|---|
| Demote `Programmed` before every apply | Every reconcile that later succeeds would flap `Programmed` to `False` and back. |
| Demote on any reconcile error through a generic deferred status handler | Cannot tell a spec rejection from a transient or observation failure, so ordinary retries would flap the condition. |
| Classify every API error returned by the loop, including reads | An RBAC or cache fault on a `Get`, or an object owned by someone else, would be reported as a rejected spec and hide the real fault. |
| Include transient API errors in the classification | Conflict, Timeout, ServerTimeout, TooManyRequests, and ServiceUnavailable resolve on retry. Demoting on them flaps `Programmed`. |
| Emit the Warning before persisting status | An Event could claim a rejection that status never recorded if the status write then fails. |
| Stricter CRD or CEL validation of `GatewayClassConfig` scheduling fields | Useful alongside reporting but not a substitute. Schema validation cannot model admission webhooks, Pod Security, quotas, RBAC, or immutable-field rules. |
| Tear down or scale down the dataplane on rejection | Takes down healthy traffic because a desired update failed. Existing objects are still valid. |
