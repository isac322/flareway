# Release gates

Apply rule://flareway-invariants.

The `e2e-gate` job in `.github/workflows/release.yaml` is the authoritative
definition of eligible evidence. This file explains the semantics; read the
workflow for the current recency window, artifact name, and required keys —
do not copy those values into other documents.

## Evidence eligibility

The gate scans recent `e2e.yaml` runs and accepts the newest one that satisfies
every condition:

- **Event**: `schedule` or `workflow_dispatch` on `main`. Pull-request runs
  (the `e2e` label trigger) never qualify — they exercise a head SHA that is
  not on `main` and may use a reduced label set.
- **Conclusion**: `success`, completed inside the gate's recency window.
- **Artifact**: the run must carry the `cloudflare-e2e-<head_sha>` artifact,
  unexpired, containing two JSON objects:
  - `e2e-latency.json` — latency records keyed by contract name. The gate
    requires keys proving the full public and Access surface ran: the public
    Gateway programmed key, the Access AUD-secret-blocked key, the Access
    application-deletion key, and at least one `access-ready-*` key. The exact
    key set lives in the gate script; the writers are the `recordLatency` calls
    in `test/e2e/`.
  - `e2e-private-warp.json` — the private WARP classification (below).

A run that fails any check is reported as a `::error::` line and the gate keeps
scanning older runs. If nothing qualifies, the release stops before `publish`.

## WARP classification

`e2e-private-warp.json` is written by `test/e2e` via
`test/e2e/internal/report.WritePrivateWARP`, which rejects any result outside
the closed set:

| `result` | Meaning |
|---|---|
| `pass` | A registered WARP device resolved the private hostname to Cloudflare synthetic addresses and HTTPS reached the backend through the tunnel. |
| `blocked: plan` | The Cloudflare account plan lacks a required private-network feature; the controller reported a plan/entitlement blocker. |
| `blocked: runner` | No registered WARP runner was declared (`FLAREWAY_E2E_WARP_DEVICE` unset), or runner DNS never returned synthetic addresses. |

All three are valid release evidence: the gate requires a *classification*, not
a pass. Any other value, a missing file, or malformed JSON disqualifies the
run. When the `warp` label was requested but the runner is not WARP-registered,
the workflow itself synthesizes the `blocked: runner` artifact so the evidence
file always exists.

## Producing qualifying evidence

- The scheduled `e2e.yaml` run requests `public,access,warp`.
- A manual dispatch must request the same `public,access,warp` set; the
  `labels` input defaults to `public,access`, which omits WARP and produces no
  classification file — such a run cannot qualify.
- `account-global` mutates account-wide device-profile state and is not part
  of release evidence; it belongs to its own targeted manual verification.
- `device_profile_kind: Default` is manual-only and mutates the human profile;
  it is not part of release evidence.
- `FLAREWAY_E2E_WARP_DEVICE` and `FLAREWAY_E2E_WARP_UNREGISTERED_DNS_SERVER`
  come from repository variables, not workflow code.

## Janitor

`make e2e-janitor` runs `test/e2e/internal/janitor/cmd`, which sweeps
Cloudflare resources whose name or comment carries the e2e ownership prefix
(`names.OwnerPrefix`) and that are older than `-older-than`. Connected tunnels
are skipped, not deleted. The `e2e-janitor.yaml` workflow runs it on a
schedule, on manual dispatch, and after every completed e2e run, using the same
`cloudflare-e2e` environment secrets. A failed or cancelled e2e run can leave
remote resources; the janitor is the cleanup path — never delete e2e-prefixed
resources by hand through the dashboard as the normal workflow.

## Conformance and CI

- `make conformance` → `hack/run-conformance.sh`: creates or reuses the kind
  cluster, installs Gateway API standard CRDs, builds and loads the controller
  image, applies the conformance `GatewayClass`, and runs the compiled
  conformance suite — from the host behind cloud-provider-kind on Linux, or as
  an in-cluster Job elsewhere. `VERSION` and `REPORT_OUTPUT` control where the
  report lands; the release workflow sets them from the tag.
- `conformance.yaml` runs the same script on push/PR/dispatch with the commit
  SHA as the version; `release.yaml` re-runs it per tag and uploads the report
  plus `artifacts/conformance/` diagnostics.
- `ci.yaml` covers generation diff, lint, unit/envtest, Envoy tests, artifact
  verification (`make verify-artifacts`), and container verification
  (`make verify-container`). The release `quality` job re-checks generated
  files, lint, and tests on the tagged commit.
