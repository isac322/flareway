# Versioning and release infrastructure

Apply rule://flareway-invariants.

The `publish` job in `.github/workflows/release.yaml` is the source of truth
for artifact names, registries, and tool versions. This file explains the
contracts; do not pin those values elsewhere.

## Versions

- **Git tag**: `v<semver>` with an optional pre-release suffix and no build
  metadata, enforced by the `metadata` job. The job emits `tag` (`v1.2.3`) and
  `version` (`1.2.3`); a `-` in the version marks the GitHub Release as a
  pre-release.
- **Chart `version` and `appVersion` are independent SemVer tracks.**
  `version` is the chart's own release number; `appVersion` records the
  controller version the chart installs by default. At release time the
  workflow packages with `--version <version>` and `--app-version <tag>`, so
  both follow the tag for official releases — but the fields remain
  semantically separate and `appVersion` keeps its `v` prefix.
- **appVersion is the default image tag.** The chart helper renders
  `repository:digest` when `image.digest` is set, else
  `repository:<image.tag or .Chart.AppVersion>`. `image.tag: ""` in
  `values.yaml` therefore means "the chart's appVersion".
- **Production installs pin by digest.** Set `image.digest` to the released
  image-index digest (published in `dist/image-digest.txt` and the release
  assets); it takes precedence over the tag. See `docs/operations/upgrade.md`.
- **No `latest`.** Nothing published by the release pipeline is tagged
  `latest`; `controller:latest` exists only as the local kustomize placeholder
  that `make deploy`/`build-installer` rewrite via `IMG`. Never document or
  automate installs against a floating tag.

## Image

- `hack/release-platforms.py` derives the platform set from the pinned Go
  builder image in `Dockerfile` (`ARG GO_IMAGE`), keeping Linux entries and
  normalizing arm64 variants. `PLATFORMS` overrides it for `make
  docker-buildx`; the release workflow always uses discovery.
- The release builds one buildx invocation for all platforms with
  `--provenance=mode=max` and `--sbom=true`, tags `ghcr.io/<owner>/flareway:<tag>`,
  and reads the image-index digest from the build metadata. It then re-inspects
  the pushed reference and fails if the published platform set differs from
  the discovered set, and fails if the per-platform SBOM count does not match.
- Cosign signs the digest reference recursively (keyless, GitHub OIDC) and the
  workflow immediately verifies it, storing the verification JSON as a release
  asset. Consumers verify with the workflow certificate identity and the
  `token.actions.githubusercontent.com` issuer.
- `make verify-container` (CI) checks the image filesystem, metadata, startup,
  and compressed size against `MAX_COMPRESSED_IMAGE_SIZE_BYTES`.

## Helm chart (OCI)

- The chart is packaged from `charts/flareway` and pushed to
  `oci://ghcr.io/<owner>/charts/flareway:<version>`; the pushed reference is
  recorded in `dist/chart-ref.txt`.
- `make chart` performs the local equivalent minus the push: lint, template
  render with CRDs, package into `dist/`.
- The chart bundles Flareway CRDs under `crds/` (kept in sync by
  `make sync-chart-crds`, which `make manifests` calls). Gateway API CRDs are
  a documented prerequisite, never bundled.

## GitHub Release

- Created by the release workflow with generated notes; pre-release tags
  produce pre-release releases.
- `dist/SHA256SUMS` covers every file in `dist/` and is verified
  (`sha256sum --check`) before upload; it ships alongside the chart archive,
  image digest, platform list, build metadata, chart reference/push log,
  Cosign verification, and the SPDX SBOM. Consumers can re-verify any asset
  against `SHA256SUMS`.

## Repository settings ownership

Ownership of GitHub repository settings is defined by
`rule://flareway-invariants` — this file only describes the mechanism.

Settings that workflows depend on — the `release` and `cloudflare-e2e`
environments, their secrets (`FLAREWAY_E2E_CF_API_TOKEN`,
`FLAREWAY_E2E_CF_ACCOUNT_ID`, `FLAREWAY_E2E_ZONE`) and variables
(`FLAREWAY_E2E_WARP_DEVICE`, `FLAREWAY_E2E_WARP_UNREGISTERED_DNS_SERVER`),
branch/tag protection, and Actions permissions — are managed as code in the
homelab Terraform configuration, not by workflow edits or ad-hoc API calls.

Runbook for a settings change:

1. Edit the flareway repository's entry in the homelab Terraform
   configuration (the GitHub provider resources for this repo).
2. Review `terraform plan` output for that workspace.
3. `terraform apply`; confirm the environment/secret/variable exists before
   relying on it in a workflow.
4. Never commit secret values — the Terraform configuration references them
   from the homelab secret store.

A release action (tag, dispatch, publish) never mutates repository settings;
if a gate fails because a setting is missing, fix the setting through the
homelab path, not the workflow.
