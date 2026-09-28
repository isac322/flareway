# Contributing

This guide covers the local toolchain, the checks CI runs, the conformance and end-to-end workflows, and the pull request rules.

## Prerequisites

- Go toolchain matching `go.mod` (currently Go 1.27.x).
- Docker or a compatible container tool for `docker-build` and
  `verify-container`.
- Helm and kind are installed into `bin/` by the Makefile when a target
  needs them; kind is required for the conformance workflow.

## Before you push

Run the same gates CI runs:

```sh
make lint-fix          # golangci-lint with autofix
make test              # unit and envtest suites
make verify-generated  # regenerate tracked artifacts; fails if the tree changes
```

If your change touches packaging — the chart, Kustomize bases, CRD
schemas, or the Cloudflare SDK surface — also run:

```sh
make verify-artifacts  # parity, Go build, Helm, Kustomize, runtime defaults
```

Never hand-edit generated output (`config/crd/bases/`,
`config/rbac/role.yaml`, `**/zz_generated.*.go`, chart CRDs). Change the
source markers or types and regenerate with `make manifests` or
`make generate`.

## Gateway API conformance run

The [conformance report](conformance/v1.6.2/flareway/README.md)
comes from this workflow. Run it with Docker, Go, and `kubectl` installed:

```sh
make conformance
```

The script creates or reuses the `flareway-conf` kind cluster, installs
Gateway API v1.6.2 and Flareway, builds the controller image, and applies
the conformance `GatewayClass`.

On Linux, it starts cloud-provider-kind and verifies that it can assign a
LoadBalancer address before running the suite from the host. On macOS, or
when the provider probe fails, it switches the conformance Service to
`ClusterIP` and runs the compiled test binary in a Kubernetes Job. The Job
writes the report to a shared volume, and the script copies it to
`docs/conformance/v1.6.2/flareway/`.

The runner disables test parallelism because Flareway deliberately uses one
controller replica and one Gateway reconciliation worker. This serializes
independent fixtures without skipping tests or weakening their assertions.

Useful overrides:

```sh
KIND_CLUSTER_NAME=my-cluster \
VERSION=dev \
REPORT_OUTPUT="$PWD/docs/conformance/v1.6.2/flareway/standard-dev-default-report.yaml" \
make conformance
```

The workflow does not invoke `sudo`. It pins kind, cloud-provider-kind, ko,
kustomize, the kind node image, and Gateway API to the versions declared in
the repository.

## End-to-end test prerequisites

The end-to-end suite runs against real Cloudflare with `make e2e`, which
selects specs by `FLAREWAY_E2E_LABELS`. It requires a dedicated test
account and zone:

- `FLAREWAY_E2E_CF_API_TOKEN`
- `FLAREWAY_E2E_CF_ACCOUNT_ID`
- `FLAREWAY_E2E_ZONE`
- optional `FLAREWAY_E2E_KUBECONFIG`
- `FLAREWAY_E2E_LABELS` (default `public,access`; add `warp` for the
  private WARP spec)
- `FLAREWAY_E2E_WARP_DEVICE=1` only on a registered WARP runner; the e2e
  workflow registers the runner itself via `hack/e2e-warp-runner.sh`
  (per-run service token, app-scoped enrollment policy, and custom device
  profile, all deleted after the run)
- optional `FLAREWAY_E2E_WARP_UNREGISTERED_DNS_SERVER`
- `FLAREWAY_E2E_DEVICE_PROFILE_KIND` and explicit
  `FLAREWAY_E2E_ALLOW_DEFAULT_PROFILE=1` before mutating the default
  profile

Use a dedicated account because the suite creates and deletes tunnels, DNS
records, Access applications, policies, and private-network objects. Record
a missing WARP runner or plan capability as blocked, not as passed or
silently skipped.

## CI caches

Every workflow job that runs Go restores one shared Go build cache entry
through the local `./.github/actions/go-cache` action, which also installs
the toolchain pinned by `go.mod`. Do not use `actions/setup-go` directly:
its built-in cache mixes the module cache into a single `go.sum`-keyed
entry that is written only on a miss, so every job races for one write and
the build cache then stays frozen until `go.sum` changes.

Only the `Go build cache` workflow writes the shared entry, and only on
`main`. GitHub scopes a cache to the branch that wrote it, so a pull
request can read `main`'s entry but never another pull request's. That job
runs `make warm-build-cache`, which compiles everything CI builds — every
package, the race and tagged test binaries, the conformance and end-to-end
binaries, and the `go install` tools — so the single entry covers every
consumer. When you add a job that runs Go, use the composite action, and
add whatever it compiles to `make warm-build-cache`.

## Commit style

History uses Conventional-Commit-style subjects:
`fix(controller): preserve tunnel status ownership`,
`docs: rewrite README`, `build(deps): bump …`. Match that shape —
type, optional scope, imperative subject.

## Pull requests

- PRs are squash-merged; keep the branch history clean enough that the
  squash commit tells one story.
- The branch must be up to date with `main` (linear history), and every
  review conversation must be resolved before merge.
- Eight checks are required to pass: Cloudflare SDK parity, Container
  build and runtime, Envoy component tests, GatewayHTTP conformance,
  Generation diff, Lint, Schema, build, Helm, and Kustomize, and Unit
  and envtest.

## Where the rules live

Area-specific guidance is documented, not tribal:

- `docs/` — install, operations, API reference, architecture decisions
  (`docs/adr/`), troubleshooting.
- `.agents/skills/` — per-area guides: API changes, reconciliation,
  security invariants, testing, releases.
- `.agents/rules/flareway-invariants.md` — the normative invariants
  (G0–G8) every change must preserve.

Read the guide for the area you are touching instead of guessing at
conventions.

## API changes

Flareway's API is `v1alpha1`; API changes are expected and
accepted. When you change a CRD kind or field, update the generated CRDs
(`make manifests`) and deepcopy code (`make generate`); `Generation diff`
fails when either is stale. Update `docs/reference/api.md` in the same
change; it is written by hand.
