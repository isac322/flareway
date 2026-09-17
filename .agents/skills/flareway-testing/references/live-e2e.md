# Live Cloudflare e2e contract

Apply rule://flareway-invariants. This reference covers the `test/e2e` suite
(`-tags e2e`, Ginkgo): prerequisites, isolation, polling discipline,
fail-closed assertions, cleanup, the janitor, WARP classification, and
diagnostics.

## Prerequisites and isolation

- Required env: `FLAREWAY_E2E_CF_API_TOKEN`, `FLAREWAY_E2E_CF_ACCOUNT_ID`,
  `FLAREWAY_E2E_ZONE`. Optional: `FLAREWAY_E2E_KUBECONFIG`,
  `FLAREWAY_E2E_CF_BASE_URL`, `FLAREWAY_E2E_LABELS`,
  `FLAREWAY_E2E_WARP_DEVICE`, `FLAREWAY_E2E_WARP_UNREGISTERED_DNS_SERVER`,
  `FLAREWAY_E2E_DEVICE_PROFILE_KIND`, `FLAREWAY_E2E_ALLOW_DEFAULT_PROFILE`.
- Missing required credentials skip the whole suite (`t.Skipf`). Never run
  against a production account or zone — the suite creates and deletes real
  remote resources.
- Run against a dedicated Kind cluster, never a dev/prod context.
  `make test-e2e` creates `KIND_CLUSTER` (default `flareway-test-e2e`) and
  deletes it afterward; `make e2e` uses the cluster your kubeconfig points at.
- Every run gets a random run ID. `test/e2e/internal/names` derives a
  per-run namespace, resource names, and hostnames under the ownership prefix
  `flareway-e2e-`; the `flareway.bhyoo.com/e2e-run` label marks the namespace.
  The suite `CloudflareAccount` grant is scoped to that label and the run's
  hostnames, so one run cannot touch another run's resources.
- The suite is `Ordered` and runs serially (`make e2e` passes a 60m timeout).
  Specs share the per-run namespace, `CloudflareAccount`, `GatewayClass`, and
  echo backend created in `BeforeSuite`.

## Polling discipline — no blind retry

- Use `poll.Until(ctx, interval, check)` for every wait. It evaluates
  immediately, then on each interval, and returns elapsed time for latency
  recording.
- A non-nil error from `check` aborts polling: deterministic API failures are
  not propagation delay and must surface, not be retried.
- Bound every poll with `context.WithTimeout` (or the Ginkgo `SpecContext` /
  `NodeTimeout`); never sleep and never poll unbounded.
- Where propagation noise is expected (e.g. a path that must stay 404), require
  consecutive identical observations rather than a single sample.
- On poll failure, print diagnostics before asserting: `conditionSummary`,
  `statusSummary`, `dataplaneDiagnostics`, `audSecretDiagnostics` exist so a
  failure message carries the object's conditions and data-plane state.

## Fail-closed edge assertions

The edge must deny on uncertainty; tests prove it rather than assume it:

- An unmatched path must never reach the origin: any 2xx is a deterministic
  failure. Acceptable denial is 404 (or the documented denial status); a
  single clean 404 suffices, otherwise require consecutive 404s so propagation
  noise cannot hide a transient leak.
- Unauthenticated Access requests must redirect to authentication (302 with an
  Access challenge), not reach the origin.
- Forged or wrong-audience JWT assertions must receive a denial or challenge —
  never 2xx.
- Deleting the AUD Secret must block the hostname (403), not disable Access.
- Deleting the `AccessApplication` must keep the hostname blocked (403/404);
  removal of protection is never a path to public.
- `deletionPolicy: Orphan` and adoption specs assert the remote object
  survives/is preserved — verify remote state through `cfapi`, not just
  Kubernetes status.

## Cleanup — reverse dependency order

- Register `DeferCleanup` or `AfterAll` deletions in reverse creation order:
  dependents before the objects they reference (routes and Access resources
  before policies, tokens, tunnels, gateways).
- After `kubectl delete`, call `waitForObjectDeletion` so finalizers finish
  before dependent remote cleanup — otherwise remote deletes hit dependency
  conflicts.
- `AfterSuite` drains the run namespace in explicit reverse-dependency tiers
  discovered through `ServerPreferredResources` and planned by
  `test/e2e/internal/cleanup`: applications; routes and Gateways; shared
  policies, groups, and virtual networks; service tokens and other leaves;
  then remaining CloudflareTunnels and WARPConnectors. Every tier deletes all
  of its objects, then waits for the whole tier to be empty so finalizers
  complete. Before the tunnel tier, the HostnameRoutes the Gateway controller
  generated into the operator namespace (labeled
  `flareway.bhyoo.com/platform-object=true` and
  `flareway.bhyoo.com/source-namespace=<run namespace>`) are deleted and
  awaited — they reference the run's tunnels and would otherwise block tunnel
  finalizers. A discovered Flareway or Gateway API kind with no tier fails
  the suite loudly — never skip it silently.
- The `CloudflareAccount` credential Secret lives in the run namespace, so
  the Namespace is deleted and awaited only after every namespaced tier has
  drained; deleting it earlier wedges tunnel finalizers with
  `CleanupBlocked/CredentialsUnavailable`. `GatewayClass`,
  `GatewayClassConfig`, and `CloudflareAccount` are deleted and awaited last;
  the janitor runs only after all of them are gone.
- A failed stage aborts all later Kubernetes teardown — later tiers, the
  Namespace, and the cluster fixtures are never touched — because continuing
  would remove credentials that live dependents still need. The failure fails
  the suite, and the in-suite janitor is skipped so remote deletes cannot
  race live resources; leftovers belong to the scheduled janitor. A janitor
  `ConnectedSkipped` tunnel after a successful drain is also a suite failure.

## Janitor

`make e2e-janitor` runs `go run ./test/e2e/internal/janitor/cmd` and sweeps
stale remote resources from interrupted runs. Safety contract:

- Refuses any prefix not starting with `flareway-e2e-` and any negative
  `-older-than`; only resources older than the cutoff are eligible.
- Deletes in reverse dependency order: Access applications (bypass children
  first), then policies, service tokens, hostname routes, network routes,
  virtual networks, DNS records, and finally tunnels.
- Skips tunnels that still have connections or report healthy/degraded status
  (`ConnectedSkipped`) — a live tunnel is never deleted.
- Per-resource failures are collected and reported, not fatal to the rest of
  the sweep.
- CI runs the janitor on a schedule and after every e2e workflow completion.

## WARP classification

The `warp`-labeled spec proves a private hostname end to end through a
registered WARP device: Gateway `Programmed`, synthetic private DNS answers,
and an HTTPS request reaching the backend.

- It always writes `artifacts/e2e-private-warp.json` with exactly one result:
  `pass`, `blocked: plan` (Cloudflare reported a missing private-network plan
  feature), or `blocked: runner` (no registered WARP device, or runner DNS
  cannot resolve synthetic private addresses).
- Blocked is a recorded outcome, not a pass and not a silent skip. CI fails if
  `FLAREWAY_E2E_WARP_DEVICE=1` was set but no classification artifact exists.
- When `FLAREWAY_E2E_WARP_UNREGISTERED_DNS_SERVER` is set, the spec also proves
  that an explicitly unregistered DNS path does not resolve the private
  hostname.

## Artifact diagnostics

- `artifacts/e2e-latency.json` — per-phase convergence durations recorded via
  `recordLatency`.
- `artifacts/e2e-private-warp.json` — the WARP classification above.
- CI additionally collects controller logs, all Flareway/Gateway resources,
  workload state, and events under `artifacts/cluster/`, with token/AUD/bearer
  redaction applied before upload.
- Artifacts must never contain API tokens, tunnel tokens, service-token
  secrets, or Access AUDs; keep diagnostics secret-free.
