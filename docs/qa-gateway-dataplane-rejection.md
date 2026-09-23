# Gateway dataplane rejection QA

## Scope and decision

A Kubernetes rejection of a Gateway-owned dataplane mutation must not leave the
Gateway claiming that its desired configuration is programmed. GatewayClassConfig
changes do not change the Gateway generation, so observedGeneration alone cannot
establish convergence.

The investigation and test-design reviewers agreed on the following contract
before implementation:

- Classify API Invalid, Forbidden, and BadRequest at the owned-object mutation
  boundary, including Create, Apply, and blocking preparatory patches.
- Preserve observation failures, ownership conflicts, and transient errors as
  retryable errors without changing programming status.
- On rejection, persist Gateway and listener Programmed=False with reason Invalid,
  and emit a Warning Event identifying the object kind, namespace/name, and API
  reason. Never copy arbitrary API error payloads into status or Events.
- Emit on the failure transition or changed rejection identity, not every retry.
  Preserve the original error and any status-write failure for retry.
- Preserve existing workloads, addresses, accepted configuration, ownership and
  authorization checks. This is status fail-closed behavior, not traffic teardown.
- Recover through the ordinary convergence gate after configuration is corrected.

## Root cause analysis

### Occurrence

The defect is a missing write on the mutation-failure path, confirmed end to end:

1. Reconcile persists the pre-reconcile Gateway status early, before the
   owned-object loop runs, so a previously persisted Programmed=True is
   re-written unchanged.
2. `prepareConditions` demotes Programmed to Unknown/Pending only when
   observedGeneration differs from generation. GatewayClassConfig edits do not
   change the Gateway generation, so the stale True survives this pass.
3. The owned-object loop returns the mutation error immediately. No code between
   the mutation boundary and the error return records the rejection in status or
   emits an Event.
4. Result: the API server durably rejects the desired dataplane object while the
   Gateway reports Programmed=True at the current generation and emits nothing.

Historical source inference versus executable confirmation:

- Source history (inference, not per-release execution): the early error return
  has existed since the root commit `ca39104`; every published release through
  `v0.2.1` carries it. The issue author observed it at `ed5f005`.
- Executable confirmation at pre-fix HEAD `5a9ba02`: an envtest reproduction
  against a real API server and etcd ran two specs. The healthy control reached
  Programmed=True. The CRD accepted a nodeSelector key of `bad key!`; a dry-run
  server-side apply of the resulting Deployment returned Invalid, and a real
  reconcile returned the same Invalid error. The Gateway remained Programmed=True
  at unchanged generation with no Warning Event. Restoring a valid nodeSelector
  recovered Programmed=True at the same generation. Both specs passed,
  confirming the defect assertions.

### Escape

- The nodeSelector key is legal to the GatewayClassConfig CRD schema; the
  deferred-validation boundary introduced with the scheduling feature means the
  failure exists only at the Kubernetes admission boundary, which no existing
  test drove to a real rejection.
- Scheduling tests documented the boundary but stopped at the CRD layer, so no
  coverage exercised an owned-object mutation failing after CRD acceptance.
- The status convergence gate runs only on the success path, so nothing
  downstream of the failed apply corrects the stale condition.

### Containment

- The error is still returned, so controller-runtime retries; the failure is a
  reporting gap, not a reconcile stall or a stuck finalizer.
- No teardown path runs on this error: existing Deployments and Services keep
  serving while the desired update is rejected.
- Blast radius is status truthfulness and operator visibility: a Gateway can
  claim Programmed indefinitely while its desired dataplane spec is rejected.

### Counterfactuals

- If transient errors (Conflict, Timeout, ServerTimeout, TooManyRequests,
  ServiceUnavailable) were demoted, ordinary retries would flap Programmed.
  Classification is therefore limited to Invalid, Forbidden, and BadRequest.
- If observation failures (GET Forbidden, re-read failures, foreign-owner
  collisions) were demoted, RBAC or cache faults would masquerade as spec
  rejection. Only errors raised by mutation calls are classified.
- If the rejection status write itself fails, dropping either error loses
  diagnostics. Both errors are joined so the retry can persist status and still
  surface the original rejection.
- If the Warning were emitted before status persistence, an Event could claim a
  rejection that status never recorded. The Event follows successful persistence
  and is deduplicated against the persisted condition.

### Extent of condition

Mutations in scope: the initial Create, the blocking managedFields migration
patch, the Service listener-port replacement patch, and the final server-side
Apply. Observation out of scope: the initial GET, the re-read after a create
collision, and the re-read after port replacement. The post-Create migration is
best-effort by design — logged and retried on the next reconcile — and stays
non-blocking; only the blocking migration on the update path can reject.

## Alternatives considered

- Unconditional preemptive demotion before applying: flaps Programmed on every
  reconcile that later succeeds. Rejected.
- Generic deferred status handler on any reconcile error: cannot distinguish a
  mutation rejection from a transient or observation failure, so it flaps on
  ordinary retries. Rejected.
- Broader CRD/CEL validation of scheduling fields: cannot model admission
  webhooks, Pod Security, quotas, RBAC, or immutable-field rules. It complements
  but cannot replace rejection reporting. Rejected as a substitute.

## QA semantics agreed before implementation

- Same-generation fixtures: transient-error and observation-failure cases run
  without changing the Gateway generation, so any spurious demotion is observable
  rather than masked by a generation bump.
- Rejection-write fault: the status-persistence failure case injects the fault at
  the rejection status write, not at the earlier pre-reconcile status checkpoint.
- Successful-Create migration: a failed best-effort migration after a successful
  Create remains a logged retry, not a rejection.
- Event ordering: the Warning is emitted only after the rejection status
  persists, deduplicated against the previously persisted Programmed
  status/reason/message; an unchanged retry keeps LastTransitionTime and emits
  nothing.

Review record: error-flow, reproduction-design, and provenance reviews reached
consensus on the contract above before implementation. An independent challenge
review approved it conditional on a real reproduction; the pre-fix envtest
reproduction described under Occurrence was executed and confirmed the defect
before any production change.

## QA checklist

| ID | Scenario | Required observation |
| --- | --- | --- |
| Q1 | Healthy control | Real envtest API accepts owned objects; available Deployment and acknowledged snapshot produce Programmed=True. |
| Q2 | Existing Deployment apply rejected | A CRD-accepted invalid nodeSelector reaches Kubernetes admission; Gateway and all listeners become False/Invalid; Gateway generation is unchanged. |
| Q3 | Initial Deployment create rejected | No desired Deployment is created; Gateway becomes False/Invalid rather than remaining Unknown. |
| Q4 | API classification | Invalid, Forbidden, and BadRequest from mutation produce rejection status and Warning; returned error remains discoverable. |
| Q5 | Transient errors | Conflict, Timeout, ServerTimeout, TooManyRequests, ServiceUnavailable and non-API errors preserve prior Programmed state and return for retry without Warning. |
| Q6 | Observation and ownership failures | GET Forbidden and foreign-owned collisions do not masquerade as admission rejection or mutate another owner's object. |
| Q7 | Preparatory mutations | Blocking managed-field migration and Service port replacement rejections follow the same reporting contract; internal observation failures remain retry-only. |
| Q8 | Event safety and repetition | Warning identifies kind and key, omits raw sensitive payloads; identical retry does not re-emit or change transition time; a changed object/reason may emit. Nil recorder is safe. |
| Q9 | Status persistence failure | Original rejection and status-write error both survive; retry can persist status and report the rejection. |
| Q10 | Recovery | Correct config without changing Gateway generation; desired scheduling is applied and normal availability/ACK gates restore Gateway and listener Programmed=True. |
| Q11 | Existing workload preservation | Rejection does not delete/scale down healthy Deployment or remove existing Service; acceptance and unrelated conditions remain intact. |
| Q12 | Regression gates | Unit/envtest, lint, generated-artifact verification and all PR CI checks pass; independent review covers error classification, SSA ownership, status/event transitions and security boundaries. |

## Verification limits

Envtest uses a real Kubernetes API server and etcd. Deployment availability and
Envoy acknowledgements are controlled inputs, not evidence of real edge traffic.
Typed API error injection exercises failures that are difficult to arrange through
admission locally; real Invalid rejection is also tested against the API server.
Passing these checks does not prove live Cloudflare availability or the absence of
all possible regressions.

The reproduction evidence above records pre-fix behavior at `5a9ba02`. Post-fix
checklist results are reported separately; this document does not assert them.
