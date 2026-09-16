---
name: flareway-security
description: Apply and verify the Flareway security invariants when changing authorization, ownership/adoption, credential, AUD/JWT, or revocation code. Use for any edit touching CloudflareAccount grants, ReferenceGrant/backend resolution, remote ownership markers, Secrets carrying credentials, AUD handoffs, token revocation, or SCIM/ServiceToken one-time capture.
---

# Flareway Security Procedures

## Mandatory first step

Read `rule://flareway-invariants` before applying any procedure here. That rule is
the sole normative owner of the G0–G8 invariants; this skill only describes how to
apply and verify them in code. Never restate, weaken, or extend an invariant in
skill text — if a procedure and the rule disagree, the rule wins and the procedure
must be fixed.

## When to use

Apply these procedures whenever a change touches:

- `internal/authz/` or any `authz.Evaluate` / `authz.Request` call site
- `internal/gatewayapi/` reference and backend resolution (`refgrant.go`, `backends.go`)
- Remote ownership, adoption, `managementPolicy`, or `deletionPolicy` handling in `internal/controller/`
- Any Secret that carries a credential, AUD, or one-time token
- AUD handoff, origin-JWT enforcement, or revocation latching
- xDS client-certificate authorization in `internal/xds/server/`

## Procedure index

| Concern | Reference |
|---|---|
| Account grants, no union across grants, ReferenceGrant + backend grant, ExternalName rejection | `references/authz-ownership.md` |
| Ownership markers, adoption, ObserveOnly, Delete/Orphan | `references/authz-ownership.md` |
| Secret/UID/provenance binding, AUD handoff, JWT enforcement, revocation | `references/credentials-access.md` |
| SCIM and ServiceToken one-time credential capture | `references/credentials-access.md` |
| xDS SPIFFE certificate authorization | `references/credentials-access.md` |

## Cross-cutting checks

Run these on every change in scope, regardless of which procedure applies:

1. **Gate before credentials.** Every new path that reads account credentials or
   calls a remote API must pass through the grant evaluator first. Discovery:
   `accessClientForAccount` and `authorizePrivateNamespace` in
   `internal/controller/` are the canonical gate wrappers.
2. **Exceptions stay narrow.** Cleanup, deletion, and revocation paths may bypass
   only the specific step they exist to perform (for example, skipping remote
   mutation under `ObserveOnly`). Grant-gated cleanup paths must still evaluate
   the namespace grant before reading credentials; CloudflareTunnel teardown is
   the separate already-verified case gated by `ownershipVerified` instead (see
   `references/authz-ownership.md`). Exceptions must never be widened into a
   general authorization bypass.
3. **Fail closed.** A missing grant, unverifiable binding, duplicate handoff, or
   unacknowledged revocation must deny or block — never fall through to allow.
4. **No secret leakage.** Credentials, AUDs, and token material must not appear in
   status fields, conditions, events, log values, or labels. Check both the write
   site and every status/log path that could echo it.
