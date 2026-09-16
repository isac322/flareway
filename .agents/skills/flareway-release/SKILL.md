---
name: flareway-release
description: Cut a Flareway release — tag shape, e2e evidence gate, conformance, signed multi-arch image, Helm OCI chart, and GitHub Release. Use when preparing, tagging, or debugging a release, or when changing release workflows, evidence requirements, or published artifacts.
---

# Flareway release

Apply rule://flareway-invariants.

A release is a tag-triggered pipeline in `.github/workflows/release.yaml`. Every
gate must pass before anything is published; there is no partial release.

## Pipeline shape

Read the workflow for the current job graph; it is the source of truth.

1. `metadata` — validates the pushed tag and derives the release version.
2. `e2e-gate` — requires recent, complete Cloudflare e2e evidence. See
   [references/release-gates.md](references/release-gates.md).
3. `quality` — generated-file diff, lint, unit/envtest, and Envoy tests.
4. `conformance` — runs `hack/run-conformance.sh` and uploads the report.
5. `publish` — multi-arch image, Cosign signature, Helm OCI chart, checksums,
   GitHub Release. See
   [references/versioning-infrastructure.md](references/versioning-infrastructure.md).

## Cutting a release

1. Confirm the e2e evidence gate will pass: a scheduled or manually dispatched
   `e2e.yaml` run on `main` must have completed successfully inside the gate's
   recency window with labels `public,access,warp` and a valid WARP
   classification. If the latest qualifying run is stale or missing, dispatch
   `e2e.yaml` with `labels: public,access,warp` and wait for it before
   tagging.
2. Push a SemVer tag matching the pattern enforced by the `metadata` job.
3. Watch the release workflow. A gate failure publishes nothing; fix the cause
   and re-tag or re-run as appropriate.

## Release action vs. repository settings

Running a release (tag push, workflow dispatch, artifact publication) is a
release action. Changing GitHub repository settings — environments, secrets,
variables, branch protection, Actions permissions — is a settings mutation and
follows the ownership rule in `rule://flareway-invariants`; the homelab
Terraform runbook is in
[references/versioning-infrastructure.md](references/versioning-infrastructure.md).
Never edit a workflow to work around a missing environment, secret, or
permission — change the settings through their owner instead.

## Local counterparts

- `make e2e` runs the Cloudflare e2e suite locally with
  `FLAREWAY_E2E_LABELS` selecting Ginkgo labels.
- `make e2e-janitor` sweeps stale e2e-owned Cloudflare resources.
- `make conformance` runs the portable Gateway API conformance workflow.
- `make chart` lints, renders, and packages the chart into `dist/`.
- `make docker-buildx` builds and pushes the image for every platform the
  pinned Go builder supports; `hack/release-platforms.py` prints that set.
- `make verify-container` checks image filesystem, metadata, startup, and
  compressed size.
