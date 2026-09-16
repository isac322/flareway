# Cloudflare parity ledger

`hack/parity` (run via `make parity`, and inside `make verify-artifacts`)
enforces a durable, reviewed mapping between the pinned Cloudflare Go SDK
schema and Flareway's CRD and client declarations. The ledger is
`hack/parity/ledger.json`; the checker's pinned expectations live as constants
at the top of `hack/parity/main.go`.

Read current values from source — never hardcode them into docs or comments:

- Pinned SDK module/version: `expectedSDKModule` / `expectedSDKVersion` in
  `hack/parity/main.go`, which must equal the direct `require` in `go.mod`.
- Expected row count and key-set digest: `expectedLedgerRows` and
  `expectedLedgerKeySHA256` in the same file.
- Audited SDK files, ignored types/fields, and per-struct SHA-256 digests:
  the `sdk` section of `ledger.json`.

## What the checker validates

- `formatVersion`, SDK module, SDK version, and row count match the pinned
  constants; `go.mod` must directly require the pinned module at the pinned
  version.
- Every row key is `audit::direction::officialPath`, unique, and the sorted
  key set hashes to the pinned digest — so any added, removed, or renamed row
  requires updating the constants.
- Every row names a registered `owner`; each owner declares real `type`/`func`
  symbols that must exist in the referenced files.
- `currentMapping` must contain at least one `path/file.go:Symbol` or
  `path/file.go:Type.Member` evidence reference, and each cited symbol must
  exist in that file. Placeholder text (`not mapped`, `unimplemented`, `tbd`,
  `todo`, bare `none`) is rejected.
- `excluded` and `transport` rows require a non-empty `rationale`.
- `complete: true` forbids `actionable` rows — a complete ledger has zero.
- Every exported struct in the audited SDK files must appear in `sdk.schema`
  with a matching SHA-256 of its source text, unless covered by an
  `ignoredTypes` rule (`contains`/`suffix` + rationale). Structs listed in the
  ledger but missing from the SDK also fail.

## Disposition contract

Each row records one audited official field or operation. Choose the
disposition by ownership, not by whether a feature exists:

| Disposition | Meaning | Requirements |
|---|---|---|
| `mapped` | The field/operation is covered by a typed Flareway path: a `spec` field, a `status` observation, a Secret capture, or a client call. | `currentMapping` cites the implementing `file.go:Symbol` evidence; `sourceVerdict` is `EXACT`. |
| `excluded` | The field is deliberately not represented: deprecated wire aliases, UI-only toggles, server-computed values that are not desired state. | Non-empty `rationale` stating why it is not a Flareway resource-schema requirement; `currentMapping` still cites where the decision is anchored. |
| `transport` | Envelope, paging, or request-traversal data (`success`, `errors`, `messages`, `result_info`, `page`, `cursor`, …) handled by the SDK transport, never CRD state. | Non-empty `rationale`; `currentMapping` cites the Flareway boundary symbol. |
| `actionable` | A real gap that still needs an owner and implementation. | Only valid while `complete` is `false`; must have an owner. |

`direction` (`request`, `response`, `both`, …), `required` (`optional`,
`required`, `read-only`, …), and `officialType` are descriptive audit metadata;
keep them accurate but they are not enumerated by the checker. Read-only
response values that Flareway surfaces (status fields, Secret captures) are
`mapped`, not `transport`.

## Updating the ledger

The ledger is hand-maintained; there is no generator. Typical flows:

### A CRD or client change alters field coverage

1. Update the affected rows' `currentMapping` evidence to cite the new
   `file.go:Symbol` locations (renamed symbols break `hasEvidenceSymbol`).
2. If coverage genuinely changed, adjust `disposition`/`rationale` and, for a
   newly covered area, add rows for each audited key.
3. If the key set changed, recompute the sorted-key SHA-256 (concatenate sorted
   `audit::direction::officialPath` keys, one per line) and update
   `expectedLedgerRows` and `expectedLedgerKeySHA256` in `main.go`.
4. Run `make parity`.

### Bumping the Cloudflare SDK

1. Update `go.mod`/`go.sum` to the new version.
2. Update `expectedSDKVersion` in `hack/parity/main.go` and `sdk.version` in
   `ledger.json` to match.
3. Run `make parity`. It reports every new or changed exported struct in the
   audited files (`unmapped newly added official SDK struct` /
   `official SDK struct changed without a ledger update`).
4. Re-audit each changed struct: refresh its `sdk.schema` SHA-256, and for new
   structs add rows per audited field with the correct disposition — or extend
   `ignoredTypes`/`ignoredFields` with a rationale when the struct is
   transport-only.
5. Recompute the key-set digest and row count if rows changed; rerun
   `make parity` until clean.

### Adding a new Cloudflare API surface (new owner)

1. Add an `owners` entry naming the area and declaring the implementing
   `type`/`func` symbols (e.g. the spec type and the client interface).
2. Add the SDK source file to `sdk.files` and its structs to `sdk.schema`.
3. Add one row per audited field/operation with owner, disposition, evidence,
   and rationale.
4. Update the pinned row count and key digest; run `make parity`.

## Failure triage

- `ledger key set does not match the audited baseline` — row keys changed;
  recompute the digest and row count in `main.go`.
- `evidence … references a missing symbol` — a rename or move; fix the
  `currentMapping` citation, never the test.
- `unmapped newly added official SDK struct` — new SDK surface; audit it into
  rows or add an `ignoredTypes` rule with rationale.
- `official SDK struct changed without a ledger update` — upstream schema
  drift; re-audit the struct and refresh its SHA-256.
- `Cloudflare SDK version is X, ledger requires Y` — `go.mod` and the pin
  disagree; align them.
- `claimed-complete ledger contains actionable key` — either implement and
  remap the row, or the ledger is not actually complete.

## Related documentation

`docs/api-reference.md` ("Parity ledger and intentional exclusions") and the
design document §5.6 record the same ownership boundary in prose: mutable
fields become typed spec, server-owned values become bounded status, envelope
and deprecated wire fields are excluded. Keep those tables consistent with
ledger dispositions when the boundary moves.
