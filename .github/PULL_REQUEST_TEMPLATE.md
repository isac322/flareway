## What changed and why

<!-- One or two sentences. Link the issue if there is one. -->

## Evidence

<!-- What you actually ran, and what it printed. For example:
     make lint-fix — clean
     make test — all suites pass
     make verify-generated — no diff
     Paste the relevant output or summarize it honestly. -->

## Affected surfaces

<!-- Which areas this touches: CRD schemas, controller reconciliation,
     Envoy/xDS, cloudflared config, Helm chart, Kustomize, docs, CI. -->

## Checklist

- [ ] `make lint-fix`, `make test`, and `make verify-generated` pass locally
- [ ] `make verify-artifacts` run (packaging, schema, or SDK-surface changes)
- [ ] Generated artifacts regenerated (`make manifests` / `make generate`) if types or markers changed — never hand-edited
- [ ] `docs/` updated if behavior, install, or API surface changed
- [ ] No secrets, account IDs, or private hostnames added (this is a public repository)
