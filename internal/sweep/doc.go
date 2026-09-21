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

// Package sweep implements the periodic drift-detection worker (D4/D5).
//
// The worker runs only on the elected leader replica (manager.Runnable +
// manager.LeaderElectionRunnable, matching internal/xds/server). For every
// ready CloudflareAccount it lists each sweepable resource kind once per
// freshness grade period and compares the remote listing against the cached
// Kubernetes objects. Detected drift closes the object's desired-hash gate
// through the Invalidator latch and emits a GenericEvent on Events() so the
// owning controller reconciles promptly.
//
// # Rate budget
//
// Every remote call is paced by a dedicated rate.Limiter (default 0.5 req/s,
// burst 1). The main reconciler budget is DefaultRequestsPerSecond = 3.5
// req/s (internal/cloudflare/client.go); 3.5 + 0.5 = 4.0 req/s, which does
// not exceed the Cloudflare account limit of 4.0 req/s. The sweep limiter is
// a separate instance: it never shares the account limiter or the Gateway
// Lists limiter, so sweeps cannot starve reconciles and reconciles cannot
// starve sweeps. When the injected CloudflareFactory implements
// sweepClientFactory (SweepClient), the returned client is already paced by
// this limiter and the package skips its own Wait to avoid double-pacing.
//
// # Trigger channel semantics
//
// The Invalidator latch is the source of truth; Events() is only a fast
// wakeup optimization. The channel is bounded and sends never block: when
// the buffer is full the event is dropped and the item is re-evaluated on
// the next pass, which re-sends it while the latch is still set. A lost
// event therefore degrades to the latch + TTL-expiry path, never to a lost
// invalidation.
//
// # Partial failure is fail-closed
//
// A listing that fails partway is never committed as a complete listing:
// the kind's judgement for that pass is abandoned entirely (result=partial),
// no object is invalidated, and no object is reported missing. Only a fully
// collected listing may produce drift items (result=ok). A definitive
// client-side rejection (HTTP 4xx) is recorded as result=error and likewise
// abandons judgement for that kind only — other kinds keep sweeping.
//
// # Orphans are observe-only
//
// Deleting a remote object is a destructive write. The sweep loop never
// deletes: remote objects that carry our ownership markers but have no
// matching Kubernetes object are reported as DriftCaseOrphan (metric + log)
// and left for the owning reconciler's teardown/finalizer path, which
// performs the required T0 fresh read before any destructive write.
//
// # Non-sweepable kinds
//
// These kinds have no account/zone-scoped list API and are deliberately not
// swept; their drift detection stays on the per-object TTL-expiry path:
//
//   - Cloudflare Tunnel ingress configuration (GetTunnelConfiguration is a
//     per-tunnel GET; cloudflared's local /config probe covers convergence)
//   - Tunnel connections (ListTunnelConnections is per-tunnel, O(objects))
//   - IdP SCIM users/groups (per-IdP endpoints only)
//   - Tunnel token (single GET, one-time capture — G6)
//   - ZeroTrustOrganization (singleton GET, not a list)
//   - DeviceSettings (singleton GET, not a list)
//
// Orphan detection is additionally limited to kinds whose remote objects
// carry an attributable ownership marker (Access owner tags, DNS comments,
// private-resource comments, cluster-prefixed names). Kinds whose remote
// name is the raw spec.name (ZeroTrustGatewayPolicy, ZeroTrustList,
// WARPConnector, AccessInfrastructureTarget, DeviceProfile) cannot prove a
// foreign object is ours, so they report missing/mismatch only.
//
// Objects under managementPolicy: ObserveOnly are skipped entirely: they
// have no desired-hash gate to invalidate, their reconciler already
// observes the remote every pass, and comparing a foreign-owned remote
// against generated names would only produce mismatches the controller
// can never fix.
package sweep
