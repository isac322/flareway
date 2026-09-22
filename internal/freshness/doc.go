/*
Copyright 2026 Byeonghoon Yoo.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package freshness implements the manager-global freshness policy (D1), the
// desired-hash gate (D2/D3), and the in-memory invalidation latch consumed by
// the sweep worker (00-architecture.md §5 contract).
//
// # Gate semantics
//
// The gate only skips remote reads. When Policy.Evaluate returns an open
// Gate, the caller may omit the remote GET/List and return early with
// RequeueAfter = Gate.Requeue (self-expiry, D10). When the gate is closed the
// caller runs the pre-existing reconcile path unchanged — the write path,
// ownership checks, and Programmed/Ready judgement are never altered by the
// gate (D3, G5). Destructive-write, adoption, WithTunnelLock, and ObserveOnly
// reads are GradeAlways (T0) and are never gated.
//
// Gate.Decision reports why the gate closed, using the same label values as
// the flareway_gate_total metric (internal/observability): "open",
// "closed_hash", "closed_ttl", "closed_invalidated". DecisionNotGated is
// returned for GradeAlways and is intentionally not a registered metric
// label — T0 reads are not gate evaluations and must not be observed as such.
//
// # Hash input discipline
//
// DesiredHash accepts any JSON-serializable input and produces a
// deterministic SHA-256 hex digest: encoding/json sorts map keys and fixes
// struct field order. Callers MUST build the input from desired state only —
// spec, UID, remoteID, accountID, clusterID (HashEnvelope is the canonical
// shape). Status fields, conditions, resourceVersion, and timestamps MUST NOT
// be part of the input: a vibrating input makes the hash change every pass
// and the gate never opens (safety condition 7). A nil input hashes
// deterministically to the digest of "null" and stays distinguishable from
// any non-nil value.
//
// # Why the latch is in-memory (verified)
//
// The Latch deliberately keeps no persistent state. The reasoning was
// verified against internal/sweep:
//
//  1. Latch entries are only ever created for kinds the sweep actually
//     sweeps (internal/sweep/targets.go). Non-swept kinds — tunnel ingress
//     configuration, tunnel connections, IdP SCIM, tunnel tokens,
//     ZeroTrustOrganization, DeviceSettings (sweep/doc.go "Non-sweepable
//     kinds") — never carry latch entries, so a restart loses nothing for
//     them. Their drift detection already relies on the per-object
//     TTL-expiry path by design.
//  2. If a restart drops a latch for a swept kind, two cases bound the
//     damage. When the object's appliedAt age is already >= TTL, the gate is
//     closed on the next reconcile and the fresh read heals the drift
//     directly. When the age is < TTL, the gate may open until the next
//     sweep pass — which runs on the same grade period — re-detects the same
//     drift and re-invalidates. In both cases the object's own TTL expiry
//     (Gate.Requeue) forces a fresh read no later than T.
//  3. The resulting worst-case drift-detection latency after a restart is T,
//     identical to the bound the architecture already accepts for out-of-band
//     drift (00-architecture.md §1). No case exists where a lost latch makes
//     drift permanently invisible: the latch is an acceleration signal, not
//     the detection mechanism.
//  4. Unlike AUD revocation state (D7/G3), a lost latch never re-opens
//     access or asserts convergence — an open gate only skips a read.
//     Persisting it to etcd would add status write churn for zero safety
//     gain.
//
// # Latch caller contract
//
// The owning reconciler MUST call Latch.Clear only after the object has
// re-converged (successful remote sync). Clearing earlier re-opens the gate
// on a still-drifted object. All Latch methods are safe on a nil receiver so
// reconcilers can treat an uninjected latch as "no invalidations".
package freshness
