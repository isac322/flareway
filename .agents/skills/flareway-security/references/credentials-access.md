# Credential and Access Procedures

Read `rule://flareway-invariants` first. These procedures apply the credential,
AUD/JWT, and revocation invariants; they do not restate them.

## 1. Secret, UID, and provenance binding

Discovery hints:

- AUD handoff Secrets: `ensureAUDSecrets`, `audSecretIdentityMatches`,
  `verifiedAUDSecrets`, `audIdentityLabel`, `liveAUDSecretBinding` in
  `internal/controller/gateway_controller.go` and
  `accessapplication_controller.go`; key/label constants in
  `api/v1alpha1/accessapplication_types.go`.
- ServiceToken Secret: `rejectServiceTokenSecretCollision`, `writeInitialSecret`,
  `writeRotatedSecret`, `cleanupPreviousCredentials` in
  `internal/controller/servicetoken_controller.go`.
- SCIM Secret: `validateSCIMSecretDestination`, `reserveSCIMSecret`,
  `captureSCIMSecret` in `internal/controller/identityprovider_controller.go`.

Procedure:

1. Each Secret kind proves its binding differently — the proof elements are
   kind-specific:
   - AUD handoff Secrets live in the operator namespace and carry no
     controller reference (the owning AccessApplication is in a tenant
     namespace). They bind by the deterministic `aud-<applicationUID>-<digest>`
     name, the `applicationId` data key equal to the remote application ID,
     namespaced-name and UID data keys for both the application and the
     Gateway, and the injective `access-application` / `aud-for-gateway`
     digest labels. `audSecretIdentityMatches` and `liveAUDSecretBinding`
     verify every element against the live objects on each read;
     `liveAUDSecretBinding` additionally rejects any Secret outside the
     operator namespace or whose namespaced key differs from the expected
     `accessAUDSecretKey`.
   - SCIM and ServiceToken Secrets bind by controller reference plus the
     remote-ID annotation (`flareway.bhyoo.com/identity-provider-id`,
     `flareway.bhyoo.com/service-token-id`).
   Never trust a Secret because its name or one label matches.
2. The controller-reference collision rule applies only to the
   controller-owned SCIM and ServiceToken Secrets: a pre-existing Secret at
   `secretRef` that fails the controller-reference check
   (`validateSCIMSecretDestination`, `rejectServiceTokenSecretCollision`) is a
   collision — surface `Conflict` or an error and stop. AUD handoffs carry no
   controller reference, so their guard is `audSecretOwnedByApplication` —
   the deterministic name prefix, identity label, and bound
   namespaced-name/UID data keys — and a foreign Secret at the deterministic
   name fails reconciliation instead of being adopted. Never adopt,
   overwrite, or merge a foreign Secret.
3. For SCIM, a credential without its exact remote-ID binding is invalid state —
   `validateSCIMSecretDestination` and `recoverSCIMProviderID` treat it as an
   error, not as a usable credential.
4. Duplicate handoffs for the same application must poison the result (drop the
   entry entirely), not pick a winner.
5. AUDs and token material never appear in status, conditions, events, logs, or
   labels. The AUD Secret lives only in the operator namespace; the
   AccessApplication status records the application ID, never the AUD.
6. AUD identity labels must be injective: derive them with a digest over
   namespace + name + UID with unambiguous separators (`audIdentityLabel`),
   bounded to the label length limit. Delimiter-joined names that can collide
   are forbidden.

Verification:

- Forged-binding tests: wrong UID, wrong namespaced name, wrong namespace, or a
  duplicate handoff must all be rejected (see the "AUD handoff identity" specs in
  `gateway_controller_test.go`).
- Collision tests: a foreign Secret at `secretRef` must produce `Conflict` and no
  write.

## 2. AUD handoff, origin-JWT enforcement, and revocation

Discovery hints:

- Handoff publication: `ensureAUDSecrets`, `audHandoffsPresent`,
  `listApplicationAUDSecrets` in `internal/controller/accessapplication_controller.go`.
- Revocation latch: `accessApplicationRevocationAnnotation`,
  `revocationAcknowledged`, `revokeApplicationTokens*`,
  `revocationTokensAlreadyRevoked` in the same file; `audRevocationState`,
  `latchAUDRevocation`, `applyAUDRevocationLatches`, `audRevocationApplied` in
  `internal/controller/gateway_controller.go`.
- Fail-closed compile: `internal/cloudflared/compile.go` (protected domain with
  no usable AUD compiles to `http_status:403`); AUD tags flow through
  `internal/ir` and `internal/gatewayapi` (`AUDSecrets`, `AccessGuard`).

Procedure:

1. Publish the AUD only through the bound handoff Secret, and only when the
   remote application actually returned an AUD and both the application UID and
   remote ID are known. A missing AUD on a protected application is an error, not
   a reason to skip enforcement.
2. Compile fail-closed: a protected domain with no verified, ready AUD — or with
   a blocked guard — produces a deny rule, never an open pass-through. Keep the
   "requires teamName and at least one non-empty audTag" validation intact.
3. Treat revocation as a latch, not an event. A deleted or distrusted handoff
   latches the (gateway, application) identity; the latch releases only after the
   tunnel reports a fresh `Blocked` status above the recorded baseline with
   desired == applied config version. Until then the handoff stays `Ready=false`
   even if a new Secret appears.
4. Only a Secret that passes the full live-binding check may latch or unlatch —
   a tenant-forged Secret in a tenant namespace must be ignored entirely.
5. Token revocation runs only after every protection domain has acknowledged
   `Blocked`, is skipped under `ObserveOnly`, and is recorded in the latch so
   retries are idempotent. Revocation still goes through the normal
   grant-gated client construction; it is a narrower operation, not an
   authorization exemption.
6. Deletion ordering: remove the AUD handoff, wait for `Blocked` acknowledgment,
   then delete bypass children, then the parent. Never delete the remote
   application while a data plane may still serve its AUD.

Verification:

- Latch tests: a latched application stays unready until the tunnel acknowledges
  `Blocked` at a newer applied version; a forged Secret cannot latch (see
  `gateway_cloudflare_test.go` revocation specs).
- Compile tests: empty AUD set on a protected domain yields the 403 rule (see
  `compile_test.go` fail-closed cases).

## 3. One-time credential capture: SCIM and ServiceToken

Discovery hints:

- SCIM: `reserveSCIMCreateIntent`, `resumeSCIMCreateIntent`,
  `findOwnedSCIMCreateJournal`, `prepareSCIMSecretForEnable`, `captureSCIMSecret`,
  `recoverSCIMProviderID` in `internal/controller/identityprovider_controller.go`;
  `scimConfig.secretRef` immutability CEL in `api/v1alpha1/identityprovider_types.go`.
- ServiceToken: `writeInitialSecret`, `writeRotatedSecret`,
  `cleanupPreviousCredentials`, `rotationApplied` in
  `internal/controller/servicetoken_controller.go`; key/annotation constants in
  `api/v1alpha1/servicetoken_types.go`.

Procedure:

1. Cloudflare returns the SCIM shared secret and the ServiceToken client secret
   exactly once, but the two flows protect the one-time value differently —
   keep them distinct.
2. SCIM journals before creating. `reserveSCIMCreateIntent` writes the pending
   remote name into the destination Secret's annotations *before* issuing the
   remote create, and the provider is created with SCIM disabled. A crashed
   reconcile resumes via `resumeSCIMCreateIntent` instead of creating a
   duplicate remote object whose secret is unrecoverable. The remote identity
   is checkpointed (`checkpointIdentityProvider`) before SCIM is enabled, and
   `captureSCIMSecret` writes the returned secret into the reserved,
   ownership-validated destination. If the Secret already holds a credential
   bound to the same remote ID, do not overwrite it; if bound to a different
   remote ID, fail. If capture fails, SCIM is disabled again so the next
   reconcile retries the enable.
3. ServiceToken captures after creating. `rejectServiceTokenSecretCollision`
   runs before `CreateServiceToken`, then `writeInitialSecret` captures the
   returned credential and stamps the `service-token-id` annotation, and the
   status patch records `tokenID` + `ownershipVerified`. There is no
   pre-create journal: a crash between the remote create and the Secret write
   orphans the remote token and loses its secret, and `recoverTokenID` only
   resumes when the Secret already carries the annotation. `secretRef` is not
   immutable for ServiceToken — the `secretRef` immutability CEL is SCIM-only —
   so the controller-reference collision check is the only destination guard.
   Do not document a ServiceToken pre-capture journal or `secretRef`
   immutability that does not exist.
4. An immutable destination Secret cannot journal or capture — SCIM detects it
   and fails early rather than losing the one-time value.
5. On ServiceToken rotation, retain the previous client ID/secret only until
   its recorded expiry, then remove those keys; never accumulate historical
   credentials.
6. For SCIM, the destination binding (`scimConfig.secretRef`) is immutable once
   set — keep the CEL rule and the controller's ownership check aligned so a
   rebound Secret cannot siphon a credential.

Verification:

- SCIM crash-recovery tests: a reconcile interrupted between remote create and
  capture must resume via the journal and still record the credential.
- ServiceToken recovery tests: a Secret carrying the `service-token-id`
  annotation recovers ownership; a missing Secret surfaces `SecretMissing`
  instead of silently re-creating.
- Rotation tests: previous-credential keys disappear after expiry and the Secret
  stays bound to the same token ID annotation.

## 4. xDS client-certificate authorization

Discovery hints:

- `AuthorizeCertificate`, `sanAuthorizationInterceptor`, `authorizedStream` in
  `internal/xds/server/auth.go`; PKI issuance in `internal/xds/pki/pki.go`.

Procedure:

1. Authorize per stream, on the first delta discovery request: the client
   certificate must contain the exact SPIFFE URI for the claimed
   `node.cluster` (`namespace/gateway` form). Exact match only — no wildcard,
   prefix, or substring matching.
2. Reject streams without verified mTLS peer information, non-delta requests, and
   any later message that changes `node.cluster`.
3. Keep the SPIFFE trust-domain prefix and the URI shape in lockstep with the PKI
   issuance side; a change on one side without the other silently denies every
   proxy.

Verification:

- Certificate tests: wrong namespace, wrong gateway name, missing URI SAN, and a
  mid-stream `node.cluster` change must all yield `PermissionDenied` (see
  `auth_test.go`).
