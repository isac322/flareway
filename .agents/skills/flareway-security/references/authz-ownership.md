# Authorization and Ownership Procedures

Read `rule://flareway-invariants` first. These procedures apply the grant,
cross-namespace, and ownership invariants; they do not restate them.

## 1. Account grant evaluation

Discovery hints:

- Evaluator: `internal/authz/evaluate.go` — `Evaluate`, `evaluateGrant`,
  `Request`, `Decision`, `Reason*` constants.
- Grant schema: `api/v1alpha1/cloudflareaccount_types.go` —
  `CloudflareAccountGrant`, `CloudflareBackendGrant`,
  `CloudflarePrivateRouteGrant`, `GrantPermission`, `Exposure`.
- Gate wrappers: `accessClientForAccount` in `internal/controller/access_common.go`,
  `authorizePrivateNamespace` in `internal/controller/private_network_common.go`.
- Translator-side call: `compileBackendObjectRef` in `internal/gatewayapi/backends.go`.

Procedure:

1. Enumerate every gate the operation needs and populate all of them in one
   `authz.Request` — hostname, zone, exposure, unprotected flag, platform-object
   flag, per-kind reference flags, `PrivateRoute`, `Backend`. A gate left unset is
   a gate skipped; never split one operation into several `Evaluate` calls to
   find a permissive combination.
2. Call `Evaluate` (directly or via a gate wrapper) before reading the credential
   Secret or constructing a remote client. In `accessClientForAccount` the order
   is: load account, require `Accepted` + `CredentialsValid`, load the request
   namespace, evaluate, then read the token Secret. Preserve that order.
3. Rely on single-grant semantics: one namespace-matching grant must permit every
   activated gate. Never merge permissions across grants, never retry with a
   reduced request after a denial, and never treat "some grant matched the
   namespace" as authorization.
4. Denials must surface as status/condition reasons (`RefNotPermitted` and
   friends), not panics, retries, or silent skips.
5. Grant-gated cleanup and deletion paths — for example AccessApplication and
   ServiceToken teardown, which build their client through
   `accessClientForAccount` — still evaluate the namespace grant, with an empty
   `authz.Request{}` when no operation-specific gate applies, before reading
   credentials. `Evaluate` always requires a namespace-matching grant, so an
   empty request is not a bypass. Do not add a "deletion mode" that skips the
   call. CloudflareTunnel teardown is the separate, already-verified case: it
   constructs its client directly (`cloudflareClient`) and is gated by
   `managementPolicy != ObserveOnly` plus `status.ownershipVerified` instead of
   a fresh grant evaluation. Keep that exception confined to tunnel teardown —
   never extend it to provisioning or to other resources.

Verification:

- Unit-test `Evaluate` for: no matching namespace grant, one grant covering all
   gates, and two grants that each cover only part of the request (must deny).
- For a new caller, assert the credential Secret is not read and the remote
   client factory is not invoked when the decision denies (see the
  `access_resources_controller_test.go` pattern of counting client calls).

## 2. Cross-namespace references: ReferenceGrant plus backend grant

Discovery hints:

- `IsCrossNamespaceReferencePermitted` in `internal/gatewayapi/refgrant.go`.
- Backend pipeline order in `compileBackendObjectRef`
  (`internal/gatewayapi/backends.go`): kind check → `ReferenceGrant` check →
  Service existence + `ExternalName` rejection → account backend grant → port and
  protocol checks.
- Access-rule references: `resolveAccessRule` / `authorizeAccessReference` in
  `internal/controller/access_common.go`.

Procedure:

1. Keep the two boundaries independent and both mandatory. A `ReferenceGrant` in
   the target namespace authorizes the Kubernetes reference; the account
   `backends` grant is the SSRF boundary on top. Neither substitutes for the
   other — a permitted `ReferenceGrant` must not skip `authz.Evaluate`, and an
   allowed backend grant must not skip `ReferenceGrant` for cross-namespace refs.
2. Reject `ExternalName` Services as backends. They resolve to arbitrary external
   DNS names and would turn a route into an SSRF primitive; the rejection must
   stay on the resolution path, not only in documentation or webhook validation.
3. When adding a new reference kind, mirror the existing order: validate
   group/kind, check `ReferenceGrant` for cross-namespace targets, verify the
   target exists and is an allowed type, then evaluate the account grant for the
   referencing namespace.
4. Denials produce route conditions (`RefNotPermitted`, `BackendNotFound`,
   `InvalidKind`) — the route is dropped from the compiled config, never
   half-programmed.

Verification:

- Exercise a cross-namespace backend with a `ReferenceGrant` but no account
  backend grant (deny), with a backend grant but no `ReferenceGrant` (deny), and
  with both (allow).
- Exercise an `ExternalName` Service backend with both grants present (still
  deny).

## 3. Ownership, adoption, ObserveOnly, Delete/Orphan

Discovery hints:

- Ownership markers: `internal/cloudflare/ledger.go` (`OwnerTag`,
  `DNSRecordComment`, `ManagedByTag`); Access tag helpers in
  `internal/controller/accessapplication_tags.go` (`accessManagedTag`,
  `accessDigestTag`, `accessIdentity`, `accessBypassTag`).
- Adoption/ownership enforcement: `internal/controller/accessapplication_adoption.go`
  (`reconcileRemoteApplication`, `verifyAccessApplicationExpectation`,
  `findOwnedParentApplication`) and `accessapplication_bypass.go`
  (`ownedBypassApplication`, `findOwnedBypassApplication`).
- Policy types: `ManagementPolicy`, `AdoptionMode`, `AdoptionExpect`,
  `DeletionPolicy` in `api/v1alpha1/cloudflaretunnel_types.go`; per-resource
  `externalRef`/`adoption` fields and their CEL rules in each `*_types.go`.
- Deletion ordering: `reconcileDelete` and `accessApplicationDeletionTargets` in
  `internal/controller/accessapplication_controller.go`.

Procedure:
1. Ownership proof is per-resource, not a universal tag:
   - Tag-capable Access applications carry the managed tag plus the
     per-resource owner tag derived from cluster ID, namespace, name, and UID.
   - ProxyEndpoint applications cannot carry tags; ownership is the checkpoint
     Secret (`access-proxy-identity-<uid>`) recording the application ID plus
     the type/domain/destinations identity and the pre-create ID baseline.
   - CloudflareTunnel ownership is explicit adoption plus
     `status.ownershipVerified` bound to `status.tunnelId` — an observed ID
     alone is not ownership.
   - DNS records carry the deterministic ownership comment derived from
     cluster ID, namespace, and owner name.
   A remote object missing its kind's proof is foreign: never update or delete
   it; report an ownership conflict.
2. Adoption is explicit. `AdoptById` requires `externalRef`; when
   `adoption.expect` is set, every declared field must match the observed remote
   object before it is touched. A mismatch is an error, never a silent
   create-or-replace. Keep the CEL rules that tie `ObserveOnly`/`AdoptById` to
   `externalRef` in sync with controller behavior when adding fields.
3. `ObserveOnly` means zero remote mutation: no create, update, delete, or token
   revocation. Report observed state and the would-apply diff instead. Check that
   every remote-write helper on the path is skipped, including revocation and
   orphan-tag stripping.
4. `DeletionPolicy` applies only to objects whose ownership proof matches.
   `Orphan` leaves the remote object in place; marker stripping is limited to
   tag-capable bypass children, which lose the managed/owner/bypass tags so
   they are not re-adopted. `Delete` removes only marker-matching objects.
   Deletion ordering for Access applications is fail-closed: AUD handoff
   first, wait for the data plane to acknowledge `Blocked`, then children,
   then the parent (see the revocation procedure in `credentials-access.md`).
5. Ambiguous creates are recovered through checkpoints/journals (for example the
   proxy-endpoint checkpoint Secret and the SCIM create-intent annotations), not
   by blind retry that could adopt a stranger's object or duplicate a remote
   resource.

Verification:

- Replay tests: a second reconcile after a converged adoption must not re-run the
  expectation check against a mutated remote (see `accessapplication_bypass_replay_test.go`).
- Ownership-conflict tests: a remote object with the right name but missing
  markers must produce a conflict error and no remote write.
- `ObserveOnly` tests: assert zero mutating calls on the fake remote client.
