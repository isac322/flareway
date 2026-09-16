# Schema and generation reference

Companion to `skill://flareway-api-change`. Apply `rule://flareway-invariants`
for normative rules; this file documents procedure and conventions only.

## File layout

- `api/v1alpha1/<kind>_types.go` — one file per kind: constants (finalizers,
  annotation keys, condition types), enum types with `+kubebuilder:validation:Enum`,
  spec/status structs, the root kind, and the list kind.
- `api/v1alpha1/groupversion_info.go` — `Group`, `Version`, `SchemeBuilder`.
  Kinds register either in `addKnownTypes` or via a per-file `init()` calling
  `SchemeBuilder.Register`; follow the pattern of the file you touch.
- `api/v1alpha1/validation_markers_test.go` — pins marker/CEL text; update it
  in the same commit as the marker change.
- `config/crd/bases/`, `config/rbac/`, `config/webhook/`,
  `api/v1alpha1/zz_generated.deepcopy.go`, `charts/flareway/crds/` — outputs of
  `make manifests` / `make generate`; ownership per G0 in
  `rule://flareway-invariants`.
- `config/samples/` — user-facing examples; keep in sync with schema changes.

## Spec vs status

- `spec`: only fields a user may set on create/update. Server-owned values
  (remote IDs, timestamps, health, `read_only` flags, computed domains or
  audiences) never appear here.
- `status`: bounded observed state — remote IDs, resolved zone IDs, observed
  collections, `metav1.Condition` list, `observedGeneration`. Status structs may
  carry compact observation types without spec-level CEL (see
  `AccessRuleObservation`).
- Credentials: user input arrives only as a Secret reference
  (`NamespacedSecretKeyReference`); credentials Cloudflare returns once at
  creation are captured in a controller-owned Secret before Ready.

## Marker conventions

- Root kind: `+kubebuilder:object:root=true`,
  `+kubebuilder:resource:scope=Namespaced|Cluster,shortName=…,categories=flareway`,
  `+kubebuilder:subresource:status`, `+kubebuilder:printcolumn` entries.
  Policy kinds also carry
  `+kubebuilder:metadata:labels="gateway.networking.k8s.io/policy=Direct"`.
- Optionality: pointer + `omitempty` for optional scalars; `+kubebuilder:default`
  for defaulted fields (`+kubebuilder:default={}` for optional structs).
- Lists: always declare `+listType=atomic|map|set`; `map` lists need
  `+listMapKey`. Bound sizes with `+kubebuilder:validation:MaxItems`.
- Unions: one pointer field per variant plus a CEL sum rule, e.g.
  `(has(self.a)?1:0)+(has(self.b)?1:0) == 1`, or
  `MinProperties=1`/`MaxProperties=1` for flat unions like `AccessRule`.
- Immutability: `+kubebuilder:validation:XValidation:rule="self == oldSelf"`.
- Cross-field rules: `XValidation` on the struct that owns the fields; write
  rules against `has(self.x)` presence, not zero values.
- Marker text and generated CRD YAML must stay ASCII (the marker test rejects
  Unicode quotes).

## Typed vs opaque fields

CRD fields are always typed structs, enums, or references — no
`map[string]any`, `json.RawMessage`, or `RawExtension` under `api/`. Opaque
maps exist only inside `internal/cloudflare` request builders that translate
typed specs into Cloudflare wire bodies. When a Cloudflare field has no typed
model yet, the correct outcome is a ledger disposition (see
`references/cloudflare-parity.md`), not an opaque CRD field.

## Reference surfaces

- `accountRef` — `corev1.LocalObjectReference` to a `CloudflareAccount`;
  required on tenant resources (CEL-enforced), same-account consistency checked
  for every referenced object.
- `targetRefs` — `[]gatewayv1.LocalPolicyTargetReferenceWithSectionName`,
  `+listType=atomic`, CEL-restricted to `gateway.networking.k8s.io` `Gateway`
  and `HTTPRoute`. Same-namespace only (cross-namespace policy attachment is
  not supported). `sectionName` selects a listener on `Gateway`, a rule name on
  `HTTPRoute`. Conflicts resolve oldest-first; the loser reports
  `Accepted=False/Conflicted`. Attachment status is reported via
  `status.ancestors[]` (`gatewayv1.PolicyAncestorStatus`).
- `parametersRef` — `GatewayClass.spec.parametersRef` must point to a
  cluster-scoped `flareway.bhyoo.com/GatewayClassConfig` (namespace must be
  unset); anything else is rejected with `Accepted=False`. A missing ref means
  built-in defaults. `Gateway.spec.infrastructure.parametersRef` may point to a
  same-namespace `CloudflareTunnel`; an unsupported group/kind yields
  `Accepted=False/InvalidParameters`.
- `ReferenceGrant` — standard upstream grant consulted for cross-namespace
  `backendRefs` and listener `certificateRefs`; denial surfaces as
  `RefNotPermitted`. `CloudflareAccount.spec.grants[].backends` is an
  additional account-level SSRF boundary layered on top, not a replacement.
- `externalRef` + `adoption` — pin an existing remote object by ID;
  `managementPolicy: ObserveOnly` observes without mutating, `AdoptById`
  requires `externalRef` and matching `adoption.expect`.

## Zero-annotation policy

Flareway reads no annotations on upstream Gateway API resources (`Gateway`,
`HTTPRoute`, etc.). All extension goes through `parametersRef`,
`targetRefs`, `tls.options`, and `infrastructure.labels/annotations`.
Flareway-written metadata is limited to typed constants declared in
`api/v1alpha1/*_types.go` (for example the GEP-713 policy label, ownership
labels on managed objects, and operational annotations on Flareway-owned
resources such as tunnel teardown or service-token rotation markers). Do not
add a user-facing annotation where a typed field or reference can express the
intent.

## Regeneration and verification

- `make manifests` — runs controller-gen for CRDs, RBAC, and webhooks into
  `config/`, then `sync-chart-crds` copies `config/crd/bases/flareway.bhyoo.com_*.yaml`
  into `charts/flareway/crds/`.
- `make generate` — runs controller-gen `object` for deepcopy methods.
- `make verify-generated` — runs `manifests` + `generate`, then fails if
  `git diff --exit-code HEAD` reports changes or if untracked files remain.
  Because it diffs against `HEAD`, run it after committing the source change;
  on a dirty worktree its diff output includes your uncommitted edits, which is
  expected locally but fails CI. To check drift without committing, run
  `make manifests generate` and inspect `git status` for unexpected changes
  under generated paths.
- `make verify-artifacts` — composes `parity`, `verify-go-build`,
  `verify-helm` (lint + template render), `verify-kustomize` (renders
  `config/crd`, `config/default`, `config/samples`), and
  `verify-runtime-defaults` (asserts rendered pod env defaults on both
  packaging surfaces). Use it when a change touches the parity ledger, the SDK
  pin, chart or Kustomize content, or container env defaults. It regenerates
  nothing; pair it with `verify-generated` when generated output is affected.
- `go test ./api/...` — runs the marker contract tests.

## Adding a new kind

1. `kubebuilder create api --group flareway --version v1alpha1 --kind <Kind>`
   (add `--controller=false` for config-only kinds such as
   `GatewayClassConfig`, `--namespaced=false` for cluster scope).
2. Name per the design catalog; the `Cloudflare` prefix is reserved for
   `CloudflareAccount` and `CloudflareTunnel`.
3. Fill in spec/status following the conventions above; register the kind with
   the scheme.
4. Add samples, docs entries, and parity-ledger owner/rows if the kind maps a
   Cloudflare API surface.
5. `make manifests generate`, then the verification gates above.
