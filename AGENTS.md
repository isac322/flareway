# Flareway — Agent Guide

Flareway is a Kubernetes operator for Cloudflare Tunnel, Access, WARP, and
Gateway API with an Envoy data plane. The repository is public.

## Architecture

Reconciliation flows through layered packages:

```
api/v1alpha1          CRD schemas and kubebuilder markers (group flareway.bhyoo.com)
internal/gatewayapi   Gateway API and Access resource resolution
internal/ir           Intermediate representation shared by translators
internal/controller   Reconcilers, finalizers, adoption, status conditions
internal/xds          xDS server and translator feeding the Envoy data plane
```

Supporting packages: `internal/cloudflare` (API client), `internal/cloudflared`
(Direct-mode config compiler), `internal/authz` (tenant/reference
authorization), `internal/dataplane` (Envoy fleet management),
`internal/observability` (metrics and events).

## Source of truth

- `PROJECT` — kubebuilder metadata; the authoritative list of API kinds.
- `config/crd/bases/` — generated CRD schemas; the field-level source of truth.
- `docs/reference/api.md` — hand-maintained/current API reference.
- `docs/adr/` — Architecture Decision Records; `docs/adr/0001-gateway-api-on-cloudflare.md` is the core design.
- `Makefile` and `.github/workflows/` — build, test, and release commands.

## Code, docs, and website must match (mandatory)

The code, the repository documentation, and the website
(https://flareway.bhyoo.com, built from `site/`) describe one product and MUST
say the same thing. A difference between any two of them is a defect of the
same severity as a failing test. There are no exceptions and no "docs later"
follow-ups.

The surfaces that must agree:

- Code and its user-visible contracts: `api/v1alpha1` and `config/crd/bases/`,
  controller behavior, status conditions and reasons, `cmd/main.go` flags and
  defaults, the Helm chart (`charts/flareway/values.yaml`, templates, schema,
  `README.md`), `config/samples/`, and the conformance report under
  `docs/conformance/`.
- Documentation: `README.md`, everything under `docs/` (concepts, get-started,
  operations, reference, ADRs, `CONTRIBUTING.md`, `SECURITY.md`), and
  `.agents/skills/**` references that state product facts.
- Website: pages synced by `site/scripts/sync-docs.ts`, the navigation in
  `site/src/data/nav.ts`, the landing copy in `site/src/data/landing-copy.ts`
  and `site/src/components/**`, and SEO metadata.

While working:

1. Every change that alters behavior, an API field, a default, a flag, a chart
   value, a sample, an install step, or a supported feature updates every
   document and website page that states it, in the same pull request.
2. Before you finish a change, search the docs, `site/src/`, and `README.md`
   for each name you touched (field, flag, value, condition reason, feature
   name, command) and fix every stale statement you find.
3. Documentation-only changes must be checked against the code they describe.
   Never document intended, planned, or remembered behavior; cite the code.
4. The site renders repository Markdown. Edit the Markdown source, never a
   generated copy under `site/src/content/docs/docs/` or `site/dist/`.

Before every merge:

1. The pull request review MUST include an explicit parity check: for each
   changed behavior, name the doc and website locations that state it and
   confirm they match the code. A review that does not report this check is
   incomplete.
2. `cd site && bun run build && bun run check` must pass, so every synced page
   and internal link resolves.
3. Any mismatch found between code, docs, and website blocks the merge until
   it is fixed in the same pull request. Reviewers treat a missing doc or site
   update as a blocking finding, not a suggestion.

## Skills

Load the matching skill before working in an area:

- `skill://flareway-api-change` — CRD/schema changes and SDK parity.
- `skill://flareway-reconcile` — controller, xDS, and dataplane work.
- `skill://flareway-testing` — test tiers, envtest, conformance, and E2E.
- `skill://flareway-security` — authorization, ownership, credentials, Access.
- `skill://flareway-release` — releases, image/chart, GitHub-Terraform, versioning.

## Invariants

Normative invariants G0–G8 live in `rule://flareway-invariants`
(`.agents/rules/flareway-invariants.md`). Apply that rule on every change; this
file intentionally does not restate it.

## Verification

Default gate after a change:

```
make lint-fix           # golangci-lint with autofix
make test               # unit + envtest suites
make verify-generated   # regenerated artifacts must leave the worktree clean
```

Run `make verify-artifacts` when the change touches packaging surfaces (Helm
chart, Kustomize config, parity ledger, container build). Run the site build
and the parity check above on every change.
