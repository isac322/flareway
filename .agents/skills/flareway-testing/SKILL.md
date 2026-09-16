---
name: flareway-testing
description: Use when writing, running, or reviewing Flareway tests — unit, envtest, Envoy component, Gateway API conformance, or live Cloudflare e2e. Covers the test pyramid, permanent-test criteria, fail-closed edge assertions, isolated Kind clusters, polling discipline, and e2e cleanup/janitor duties.
---

# Flareway testing

Apply rule://flareway-invariants. This skill adds test-mechanics guidance only;
it never restates the invariants.

## Test pyramid

| Tier | Command | Proves |
|---|---|---|
| Unit | `make test-unit` | Pure-Go logic outside `internal/controller`: translators, Cloudflare client behavior against `test/cfstub`, janitor, parity, sample validation |
| envtest | `make test-envtest` | Reconcilers against a real API server + etcd with fake Cloudflare clients |
| Both | `make test` | `test-unit` + `test-envtest` |
| Envoy component | `make test-envoy` | `-tags envoy`; boots a real Envoy container from a translated snapshot — config validates and traffic behaves |
| Gateway conformance | `make conformance` | Upstream Gateway API suite on a dedicated Kind cluster via `hack/run-conformance.sh` |
| Live Cloudflare e2e | `make e2e` / `make test-e2e` | `-tags e2e` Ginkgo suite against the real edge; needs a dedicated test account |

Per-tier detail: `references/test-pyramid.md`. Live e2e contract:
`references/live-e2e.md`.

## Permanent-test criteria

Keep a test only if it defends an observable contract and a plausible bug would
fail it:

- Assert what a consumer observes: status conditions, edge HTTP responses,
  remote Cloudflare state, emitted events.
- Exercise behavior, boundaries, invariants, transitions, precedence, and real
  errors.
- Never pin implementation: wiring, field copies, defaults, forwarding, mock
  echoes, or source text.
- Never pad: same-path parameter rows, tautologies, bare not-throw, non-empty
  checks.
- Deterministic, isolated, and safe under the full suite.
- An existing test that pins wording, implementation, or incidental behavior
  must be deleted, not re-pinned.

## Non-negotiables

- **Fail-closed edge assertions.** A protected or unmatched path returning 2xx
  is a deterministic failure, never a retry. See `references/live-e2e.md`.
- **No blind retry.** Poll with `test/e2e/internal/poll.Until` under a context
  timeout; a non-nil check error aborts polling because deterministic API
  failures are not propagation delay. Where propagation noise is expected,
  require consecutive identical observations.
- **Isolated clusters.** Conformance and e2e run on dedicated Kind clusters,
  never a dev/prod context. `make test-e2e` creates and tears down its own.
- **Cleanup in reverse dependency order.** Delete dependents before
  dependencies and wait for finalizers before removing what they protect.
  `make e2e-janitor` sweeps stale remote resources.
- **WARP classification.** The private-WARP spec always writes a classification
  artifact; missing prerequisites are recorded as blocked, never silently
  skipped or passed.

## Choosing a tier

- Reconcile, status, ownership, or adoption logic → envtest (fake Cloudflare)
  or unit (fake client).
- xDS translation correctness → unit; Envoy-observable behavior →
  `make test-envoy`.
- Gateway API surface claims → `make conformance`.
- Anything claiming the real edge, DNS, Access, or WARP works → live e2e only;
  lower tiers cannot prove it.
