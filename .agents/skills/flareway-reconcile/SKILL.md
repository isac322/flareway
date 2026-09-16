---
name: flareway-reconcile
description: "Debug and change Flareway controller reconciliation, status, finalizer, drift, and data-plane convergence. Trigger: reconcile loops, stuck conditions, CloudflareTunnel/Gateway status, cloudflared config versions, Envoy xDS ACK/NACK, teardown, adoption conflicts."
---

# Flareway Reconcile

Use this skill when working on anything under `internal/controller/`, the
`CloudflareTunnel`/`Gateway` status contract, the cloudflared remote
configuration, or the Envoy Delta xDS convergence path.

Apply `rule://flareway-invariants`. For ownership, authorization, credentials,
Access guard, or secret-handling questions, apply `skill://flareway-security`
instead of re-deriving those rules here.

## Root cause before patch

Never edit a controller to make a symptom disappear. First prove which stage
of the pipeline is stuck, in this order:

1. **Read the conditions.** `kubectl get` and `kubectl describe` the CR,
   the owning `Gateway`, and the `CloudflareAccount`. Every Flareway
   condition carries `observedGeneration`; a condition older than
   `metadata.generation` describes a previous spec, not the current one.
2. **Read the Events.** Warning Events fire only on transitions into
   `Conflict`, `CleanupBlocked`, or `SecurityBlocked`. Their messages are
   sanitized; the condition message carries the detail.
3. **Identify the owning writer.** `CloudflareTunnel` status is split between
   two field managers. Check which half is stale before assuming a bug.
4. **Check the remote projection.** `status.tunnelId`, `status.configVersion`,
   `status.dnsRecords`, and `status.hostnames` are the controller's record of
   remote truth. Compare them against the desired state before touching spec.
5. **Only then** change code or spec, and re-run the narrowest test that
   exercises the failing stage.

## Status condition evidence

`CloudflareTunnel` conditions and what proves each:

| Condition | Evidence it is working |
|---|---|
| `Accepted` | Spec authorized against the account grants and a live owner |
| `TunnelReady` | Remote tunnel exists, validated, token Secrets written |
| `ConfigApplied` | Remote config version applied; Gateway-mode writer is the Gateway controller |
| `DNSReady` | Every managed record exists with the Flareway ownership comment |
| `Ready` | `TunnelReady && ConfigApplied && DNSReady`; forced `False`/`ObserveOnly` under `ObserveOnly` |
| `CleanupBlocked` | Ordered teardown is waiting; message names the stage |
| `Conflict` | Ownership, adoption, DNS, or remote-writer conflict |

`Gateway` `Programmed` requires the full Cloudflare gate: Envoy xDS ACK,
every active cloudflared Pod on the desired config version, and managed DNS
present. The condition message lists the lagging items verbatim.

## Direct vs Gateway tunnel writer

`CloudflareTunnel.spec.configuration.mode` selects the remote-config writer:

- **Gateway** (default): the `GatewayReconciler` is the sole writer of the
  remote cloudflared configuration and of `status.configVersion`,
  `status.hostnames`, `status.listeners`, `ConfigApplied`, and
  `PrivateListenerDegraded`. The tunnel controller never writes those fields
  in Gateway mode. Ownership is UID-bound via `status.gatewayRef` +
  `status.gatewayUid`; every Gateway-side write revalidates the live Gateway
  UID and `ownershipVerified` first.
- **Direct**: the `CloudflareTunnelReconciler` writes the whole-object config
  compiled from `configuration.direct` and owns `ConfigApplied` itself. A
  Gateway referencing a Direct tunnel is rejected.

See `references/controller-lifecycle.md` for the reconcile skeleton,
finalizer/teardown order, ownership selection, adoption, drift detection, and
the status field-manager split.

## Convergence diagnostics

When `Programmed` stays `False`, work the gate in order — see
`references/dataplane-xds.md` for the full procedure:

1. `cloudflared` Pods: `/ready` returns 200 and `/config` reports the desired
   version on every active Pod.
2. Envoy: the Delta ADS stream ACKed the published snapshot version; a NACK
   or a missing stream blocks convergence.
3. DNS: every public listener hostname has a record in
   `status.dnsRecords` (skipped for `dns.mode: External`).
4. Private listeners: `DeviceSettings` proxy flags, ready `VirtualNetwork`,
   ready `HostnameRoute`, and the origin-JWT TLS contract.

## References

- `references/controller-lifecycle.md` — reconcile/status/finalizer/requeue/
  drift patterns, ownership and adoption, Direct vs Gateway write paths.
- `references/dataplane-xds.md` — Gateway/cloudflared/Envoy roles, Delta xDS
  ACK/NACK tracking, readiness/config/DNS gating, JWKS diagnostics, and the
  block-first handoff.
