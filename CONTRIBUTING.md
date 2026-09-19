# Contributing

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

- `docs/` — install, operations, API reference, design, troubleshooting.
- `.agents/skills/` — per-area guides: API changes, reconciliation,
  security invariants, testing, releases.
- `.agents/rules/flareway-invariants.md` — the normative invariants
  (G0–G8) every change must preserve.

Read the guide for the area you are touching instead of guessing at
conventions.

## API changes

Flareway is experimental (`v1alpha1`); API changes are expected and
accepted. When you change a CRD kind or field, update the generated CRDs
(`make manifests`), deepcopy code (`make generate`), and
`docs/api-reference.md` in the same change — `Generation diff` fails
otherwise.
