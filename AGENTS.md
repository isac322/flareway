# Flareway — Agent Guide

Flareway is a Kubernetes operator for Cloudflare Tunnel, Access, WARP, and
Gateway API with an Envoy data plane. It is experimental and the repository is
public.

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
- `docs/api-reference.md` — hand-maintained/current API reference.
- `docs/design/001-cloudflare-gateway-api-integration.md` — design document.
- `Makefile` and `.github/workflows/` — build, test, and release commands.

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
chart, Kustomize config, parity ledger, container build).
