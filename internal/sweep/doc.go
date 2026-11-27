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
// ready CloudflareAccount it lists each selected target from the enabled
// controller groups once per freshness grade period and compares the remote listing against the cached
// Kubernetes objects. Detected drift closes the object's desired-hash gate
// through the Invalidator latch and fans out a GenericEvent on EventsFor(kind)
// so the owning controller reconciles promptly.
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
// The Invalidator latch is the source of truth; EventsFor(kind) is only a fast
// wakeup optimization. The channel is bounded and sends never block: when
// the buffer is full the event is dropped and the item is re-evaluated on
// the next pass, which re-sends it while the latch is still set. A lost
// event therefore degrades to the latch + TTL-expiry path, never to a lost
// invalidation.
//
// # Partial failure is fail-closed
//
// A listing that fails partway is never committed as a complete listing:
// the kind's judgement for that pass is abandoned (result=partial), no
// object is invalidated, and no object is reported missing. Only a fully
// collected listing may produce drift items (result=ok). A definitive
// client-side rejection (HTTP 4xx) is recorded as result=error and likewise
// abandons judgement for that kind only — other kinds keep sweeping.
//
// Exceptions: the DNS target (`sweepDNSRecords`) and the four zone-scoped Access
// targets (`AccessApplication`, `AccessStandaloneApplication`, `AccessGroup`,
// `ServiceToken` via `listAccessScoped`). A multi-scope listing that fails for
// some zones returns a *scopedListingError. The pass is still partial —
// last-success stays stale and the aggregate names the failed scopes — but
// items judged against completed scopes are safe and are dispatched normally.
// Account-scope failures on Access targets still abort fail-closed. Scopes that
// did not list contribute no records and no judgement, and Access objects with
// a distinct checkpointed `status.zoneId` require both target and checkpointed
// scopes in `listed` (`accessScopeListed`), while partial passes also withhold
// judgement for `AccessGroup` objects whose `Accepted`/`Ready` conditions do not
// yet confirm the recorded binding for their current generation
// (`unverifiedScope`), so an unlisted zone or inherited/interrupted zone
// checkpoint can never produce a false missing verdict (non-AccessGroup objects
// with local failures such as `ServiceToken` `SecretMissing` still get judged).
//
// # Content confirmation
//
// Identity checks (remote ID, name, ownership tags) cannot see a remote whose
// content was edited out of band. When the Invalidator also implements
// ContentConfirmer, every classify call hands each matched object whose
// identity checks passed to ConfirmContent, together with the time the pass
// started (contentCheck). The owning reconciler decides per object whether a
// listing can confirm it by registering a content baseline after its own
// verify: a listed object that matches the baseline counts as a fresh verify
// and keeps the object from reading the remote itself; one that does not is
// a DriftCaseMismatch like any other. `classify` invokes ConfirmContent only
// for objects whose required scopes passed `opts.listed(ref)`, so a strict
// target confirms nothing on any failure and a scoped-partial Access pass
// confirms only objects whose relevant scopes completed listing. The DNS target
// does not use classify and confirms nothing.
//
// When any eligible `AccessApplication` (whose target and checkpointed scopes
// completed listing) references identity providers or custom pages, the same
// pass also lists those account-wide targets. A failure listing either
// referenced set aborts the pass fail-closed and confirms nothing.
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
