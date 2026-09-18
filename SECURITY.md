# Security Policy

## Supported versions

Flareway is experimental software at API version `v1alpha1`. There is no
LTS line and no backport policy: only the most recent release receives
fixes. If you are running an older tag, upgrade before reporting a bug
that may already be fixed.

## Reporting a vulnerability

Email **bhyoo@bhyoo.com**. GitHub private vulnerability reporting is not
enabled for this repository yet, so email is the only private channel.

Do not open a public issue, pull request, or discussion for a suspected
vulnerability.

The maintainer reads and acknowledges reports when able; there is no
guaranteed response time. If you have not heard back and the issue is
urgent, send a follow-up to the same address.

## What to include

- Affected version tag or commit SHA.
- How Flareway is installed (Helm chart or checkout) and the relevant
  configuration, with account IDs, tokens, and private hostnames removed.
- Steps to reproduce, including the custom resources involved.
- Impact: what an attacker or misconfiguration can reach or change.

## Security-sensitive surfaces

Reports are especially welcome for weaknesses in the areas the project's
invariants protect:

- Tenant and reference authorization resolved before any provisioning or
  remote Cloudflare call.
- Per-resource ownership and provenance checks, including `ObserveOnly`
  resources performing no remote mutation.
- Fail-closed access enforcement and retained revocation state.
- Credential handling: API tokens and one-time credentials in
  controller-owned Secrets, never in status or logs.
- `Cf-Access-Jwt-Assertion` (AUD/JWT) verification at the Envoy data
  plane.

The normative rules live in
[`.agents/rules/flareway-invariants.md`](.agents/rules/flareway-invariants.md);
this file names the surfaces rather than restating them.
