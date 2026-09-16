---
name: flareway-invariants
description: Normative invariants G0-G8 for every Flareway change; the single owner of these rules.
alwaysApply: true
---

# Flareway invariants

These invariants are normative for every change in this repository. Skills and
docs reference this file; they must not restate it.

- **G0 — Generated files and scaffold markers.** Never edit generated output
  (`config/crd/bases/`, `config/rbac/role.yaml`, `**/zz_generated.*.go`,
  `PROJECT`, chart CRDs synced by `make manifests`) and never remove
  `// +kubebuilder:scaffold:*` markers. Regenerate with `make manifests` /
  `make generate` instead.
- **G1 — Authorize before provisioning.** Resolve tenant and reference
  authorization before any provisioning, credential, or remote Cloudflare
  call. Cleanup and revocation of objects whose ownership is already verified
  stay permitted.
- **G2 — Ownership and provenance.** Ownership checks are per-resource and
  provenance-bound. Under `managementPolicy: ObserveOnly` a resource performs
  no remote or credential mutation; status and finalizer updates remain
  allowed.
- **G3 — Access fails closed.** Access enforcement is block-first: on
  uncertainty, deny. Revocation state is retained so removed grants cannot
  silently re-open access.
- **G4 — Single tunnel-config writer.** Exactly one writer owns the tunnel
  configuration per mode (`Gateway` vs `Direct`); mode transitions drain and
  tear down safely before the other writer takes over.
- **G5 — Programmed means converged.** Report `Programmed` on a Gateway only
  when xDS, the Envoy data plane, Cloudflare edge configuration, and DNS have
  all converged to the desired state.
- **G6 — Capture one-time credentials.** Credentials returned only at creation
  time are captured durably (controller-owned Secret) before the resource is
  reported Ready.
- **G7 — GitHub state via Terraform.** Repository settings, environments,
  secrets, and branch protection are owned exclusively by the homelab
  Terraform path; never manage them through other tooling or by hand.
- **G8 — Public repository hygiene.** This is a public repository: never
  commit private tenant names or configuration, secrets, or session artifacts
  (run IDs, transcripts, local dumps).

## Maintainer note

Keep the frontmatter to `name`, `description`, and `alwaysApply: true`. Adding
`condition`, `astCondition`, `agents`, or `globs` makes the rule conditional
and removes its always-apply stickiness.
