# Flareway test pyramid

Apply rule://flareway-invariants. This reference details each tier's mechanics
and what it can and cannot prove.

## Tier 1 — Unit tests (`make test-unit`)

Runs `go test` over every package except `internal/controller`. No API server,
no Docker, no network.

- `test/cfstub` is a strict, stateful in-process Cloudflare API stub owned by
  one test (`cfstub.New(t)` registers cleanup). Routes match in registration
  order; `Server.Fault` injects deterministic status/delay/`Retry-After`
  responses a bounded number of times; `Server.Journal` returns redacted call
  records and `AssertOrder` checks call ordering.
- Covers translators (`internal/xds/translator`, `internal/gatewayapi`),
  Cloudflare client retry/error handling (`internal/cloudflare`), janitor
  safety rules, parity ledger checks, and `config/samples` strict-decode and
  RBAC marker validation.
- Unit tests here run under `make test` and CI on every change; keep them fast
  and deterministic.

## Tier 2 — envtest (`make test-envtest`)

Runs `go test ./internal/controller/...` with `KUBEBUILDER_ASSETS` resolved by
`setup-envtest` (target `setup-envtest` downloads the binaries into `bin/`).

- `internal/controller/suite_test.go` starts a real API server + etcd, loads
  the generated CRDs from `config/crd/bases` plus the Gateway API standard CRDs
  from the module cache (`make gateway-api-crds` prints that directory), then
  starts the real manager with every reconciler registered.
- Cloudflare is replaced by per-resource fake clients; the xDS snapshot
  publisher is a fake that records ACK/NACK. `test/envtesthelpers` fabricates
  the status a real kubelet would report: `MarkDeploymentAvailable`,
  `CreateDataplanePods`, `CreateEndpointSlice`.
- Proves: admission, RBAC, finalizer ordering, condition transitions,
  ownership/adoption decisions, and cross-resource references — against real
  API machinery.
- Cannot prove: Envoy behavior, cloudflared behavior, or anything at the real
  Cloudflare edge.

## Tier 3 — Envoy component tests (`make test-envoy`)

Runs `go test -tags envoy ./test/envoy/...` through a temporary modfile so the
pinned toolchain directive is not rewritten. Requires a working Docker daemon;
`requireDocker` fails the test rather than skipping.

- `translator.Build` output (an xDS snapshot) is converted to a static Envoy
  bootstrap: RDS route configs are inlined, EDS clusters become STATIC with
  their load assignments, and downstream TLS secrets are inlined.
- `validateWithEnvoy` runs `envoy --mode validate` on the bootstrap;
  `startEnvoy` boots the pinned Envoy image and tests drive real HTTP through
  the listener port.
- Proves: the generated config is accepted by Envoy itself, JWT authn denies
  forged/wrong-audience tokens at the proxy, and CORS preflights are answered
  locally without hitting the backend.
- Cannot prove: cloudflared tunnel wiring or Cloudflare edge behavior.

## Tier 4 — Gateway API conformance (`make conformance`)

`hack/run-conformance.sh` is the portable workflow:

- Creates the dedicated Kind cluster `KIND_CLUSTER_NAME` (default
  `flareway-conf`) from `hack/kind-config.yaml` if absent; `make kind-up` does
  the same creation step alone.
- Installs the Gateway API standard CRDs at `GATEWAY_API_VERSION`, builds the
  controller image, deploys `config/default`, and waits for rollout.
- On Linux it starts `cloud-provider-kind` and probes a LoadBalancer Service;
  if an address is assigned, the suite runs directly from the host
  (`go test -tags conformance`, host GatewayClassConfig). On other platforms,
  or when the provider never assigns an address, it falls back to compiling
  `test/conformance` (`-tags conformance`) into a runner image executed as an
  in-cluster Job against the ClusterIP GatewayClassConfig.
- Writes the report to `conformance/reports/<gateway-api-version>/flareway/`
  and runner logs to `artifacts/conformance/`. `CONFORMANCE_RUN_TEST` narrows
  to one upstream test.
- The suite runs serially (`DisableParallelTests`) because Flareway v1
  serializes Gateway reconciliation; this preserves every assertion without
  skipping tests.

## Tier 5 — Live Cloudflare e2e (`make e2e`, `make test-e2e`)

- `make e2e` runs `go test -tags e2e -timeout 60m ./test/e2e` serially with
  `-ginkgo.label-filter="$(FLAREWAY_E2E_LABELS)"` (default `public,access`).
  It expects an existing cluster; `FLAREWAY_E2E_KUBECONFIG` selects it.
- `make test-e2e` is a different, riskier entry point, not `make e2e` plus
  Kind: `setup-test-e2e` creates an isolated Kind cluster (`KIND_CLUSTER`,
  default `flareway-test-e2e`), then it runs
  `go test -tags=e2e ./test/e2e/ -v -ginkgo.v` with no label filter — every
  spec runs, including `account-global` and `warp` — and no explicit timeout,
  so the `go test` default applies. `cleanup-test-e2e` runs only after a
  successful `go test`; a failed run leaves the Kind cluster behind. For
  routine live runs prefer `make e2e` with `FLAREWAY_E2E_LABELS` set, or the
  `e2e` GitHub workflow (labels input, 60m job timeout).
- Required env: `FLAREWAY_E2E_CF_API_TOKEN`, `FLAREWAY_E2E_CF_ACCOUNT_ID`,
  `FLAREWAY_E2E_ZONE`. Missing credentials skip the suite — never point it at
  a production account; it creates and deletes real tunnels, DNS records,
  Access applications, policies, and private-network objects.
- Labels: `public`, `access`, `lifecycle`, `account-global`, `warp`.
  `account-global` mutates account-wide device profiles;
  `FLAREWAY_E2E_DEVICE_PROFILE_KIND=Default` additionally requires
  `FLAREWAY_E2E_ALLOW_DEFAULT_PROFILE=1`.
- Full contract (isolation, polling, cleanup, janitor, WARP classification,
  diagnostics): `references/live-e2e.md`.

## Adjacent verification (not test tiers)

`make verify-artifacts` (parity, Go build, Helm, Kustomize, runtime defaults),
`make verify-generated`, `make verify-container`, and `make lint` are CI gates.
They complement the pyramid; they do not replace any tier.

`make test-exploratory` is Rapid state-machine search against envtest and
`test/cfstub`. It is not a pyramid tier and not live e2e. What the machines
are: `exploratory-tests.md`. When to run them:
`exploratory-operations.md`.

## What each tier cannot prove

| Claim | Minimum tier that proves it |
|---|---|
| Reconcile logic, conditions, finalizers | envtest |
| Envoy accepts and enforces the config | `make test-envoy` |
| Gateway API conformance report | `make conformance` |
| Real DNS, tunnel, Access, or WARP behavior | live e2e only |

Never claim edge behavior from envtest or unit evidence alone.
