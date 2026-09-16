---
name: flareway-api-change
description: Change Flareway CRD kinds, fields, kubebuilder/CEL markers, or the Cloudflare SDK parity ledger. Covers schema conventions, targetRefs/parametersRef/ReferenceGrant, zero-annotation policy, generated-artifact regeneration, and the parity audit procedure. Use for any edit under api/, config/crd, or hack/parity.
---

# Flareway API change

Apply `rule://flareway-invariants` on every change; it is the sole owner of the
normative invariants (including generated-file handling) and is not restated
here.

## When to use

- Adding, renaming, or removing a CRD kind or any `spec`/`status` field.
- Editing kubebuilder or CEL `XValidation` markers in `api/v1alpha1/*_types.go`.
- Changing how a resource references other objects (`accountRef`, `targetRefs`,
  `parametersRef`, `externalRef`, Secret references).
- Bumping the pinned Cloudflare Go SDK or updating `hack/parity/ledger.json`.

## Sources of truth

Read current values from source; never copy counts or versions into docs:

- `PROJECT` — kubebuilder metadata; authoritative kind list and scope.
- `api/v1alpha1/groupversion_info.go` — API group and version constants.
- `config/crd/bases/` — generated OpenAPI schema (ownership per G0 in `rule://flareway-invariants`).
- `Makefile` — generation and verification targets.
- `hack/parity/main.go` — pinned SDK module/version, ledger expectations.
- `go.mod` — the SDK version the parity pin must match.
- `docs/design/001-cloudflare-gateway-api-integration.md` — design contract.

## Workflow

1. Edit `api/v1alpha1/*_types.go` (types, markers, doc comments). For a new
   kind, scaffold with `kubebuilder create api` so `PROJECT` and the file
   layout stay consistent.
2. Regenerate: `make manifests generate`. This refreshes CRDs under
   `config/crd/bases/`, syncs them into `charts/flareway/crds/`, rebuilds RBAC
   and webhook manifests, and rewrites `zz_generated.deepcopy.go`.
3. Update `api/v1alpha1/validation_markers_test.go` when you add or change CEL
   rules or markers it pins, and `config/samples/` when the user-facing shape
   changes.
4. Update `docs/api-reference.md` and `docs/api/README.md` when the public API
   surface changes.
5. If the change alters Cloudflare field coverage, the SDK pin, or
   `internal/cloudflare` declarations, update the parity ledger — see
   [references/cloudflare-parity.md](references/cloudflare-parity.md).
6. Verify — see below.

## Design contract (summary)

Details and rationale: [references/schema-and-generation.md](references/schema-and-generation.md).

- `spec` holds user-mutable desired state; `status` holds bounded observed
  state (remote IDs, timestamps, conditions, `observedGeneration`). Server-owned
  or `read_only` values never appear in `spec`.
- CRD fields are always typed. Opaque maps (`map[string]any`,
  `json.RawMessage`, `RawExtension`) belong only to `internal/cloudflare` wire
  adapters; never in `api/`.
- Secrets enter via Secret references (`NamespacedSecretKeyReference`), never
  inline. Create-only remote credentials are captured in controller-owned
  Secrets.
- `targetRefs` is GEP-713 policy attachment, same-namespace only, restricted by
  CEL to `gateway.networking.k8s.io` `Gateway`/`HTTPRoute`. `parametersRef`
  binds `GatewayClass` to `GatewayClassConfig` and `Gateway.spec.infrastructure`
  to `CloudflareTunnel`. Cross-namespace backend/certificate references go
  through `ReferenceGrant`; `CloudflareAccount.spec.grants[].backends` adds an
  account-level SSRF boundary on top.
- Zero-annotation: Flareway reads no annotations on upstream Gateway API
  resources. Extension points are `parametersRef`, `targetRefs`, `tls.options`,
  and `infrastructure.labels/annotations`. Flareway-written annotations and
  labels are typed constants in `api/v1alpha1/*_types.go`.
- Kind naming: the `Cloudflare` prefix is reserved for `CloudflareAccount` and
  `CloudflareTunnel`; other kinds use the approved catalog names in the design
  document.

## Verification

- `make manifests generate` — regenerate after every `api/` or marker edit.
- `make verify-generated` — run after committing the change (or accept that the
  diff output includes your uncommitted source edits): it reruns generation and
  fails on any `git diff` against `HEAD` or on untracked files. This is the
  generated-drift gate CI runs.
- `make parity` — fast check after touching `hack/parity/ledger.json` or
  `internal/cloudflare` declarations.
- `make verify-artifacts` — run when the change touches the parity ledger, the
  SDK pin, the Helm chart, Kustomize surfaces, or container env defaults. It
  composes `parity`, `verify-go-build`, `verify-helm`, `verify-kustomize`, and
  `verify-runtime-defaults`. It does not regenerate, so run
  `verify-generated` first when generated output is affected.
- `go test ./api/...` — marker contract tests.
