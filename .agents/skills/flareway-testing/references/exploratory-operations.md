# Exploratory test operations

Apply `rule://flareway-invariants`. This note says when to run the Rapid
state-machine suite and how to treat its results. It does not describe the
machines themselves; see `exploratory-tests.md`.

## When to run it

Run exploration to search lifecycle sequences that a handwritten envtest case
does not already cover: grant loss during cleanup, Gateway/Direct handoff,
remote drift while dependents still exist, manager restart, transient API
faults.

Use it after a controller or authorization change that adds states, or when
you want a new seed to try combinations the last run did not draw.

A failure is a candidate, not a product bug. Reproduce it, decide whether the
oracle or the controller is wrong, and only then change code. A confirmed
controller defect belongs in the lowest pyramid tier that can catch it
(`make test-unit` or `make test-envtest`), not as a Rapid sequence left to
chance.

## When not to run it

Do not use exploration as a PR-blocking proof that Cloudflare, DNS, Access, or
WARP work. Those claims need live e2e.

Do not treat one green seed as coverage of the state space. It only proves the
sequences that seed drew.

Do not run it against a real Cloudflare account. The harness talks to
`test/cfstub`.

Do not keep a Rapid failfile as the regression test. Shrink, understand, and
write a focused unit or envtest case.

## Commands

Compile and race-test the deterministic trace helpers (this is the PR CI
gate):

```sh
make test-exploratory-compile
```

Run the four exploratory binaries as separate processes:

```sh
make test-exploratory \
  EXPLORATORY_SEED=<positive integer> \
  EXPLORATORY_CHECKS=<positive integer> \
  EXPLORATORY_STEPS=<positive integer>
```

Defaults: `EXPLORATORY_SEED=1`, `EXPLORATORY_CHECKS=25`, `EXPLORATORY_STEPS=8`,
`EXPLORATORY_TEST_TIMEOUT=15m` per process. The make target rejects any of
those three values that is not a positive integer.

Each process is one of `TestAccessStateMachine`, `TestGatewayStateMachine`,
`TestNetworkRouteStateMachine`, `TestSmokeAccountVerificationRoundTrip`.

## Seed, checks, and steps

`pgregory.net/rapid` draws actions from a PRNG. `EXPLORATORY_SEED` selects
that stream. The same seed, checks, and steps draw the same action sequence.
A different seed draws a different sequence, so the reachable object
combinations change.

`EXPLORATORY_CHECKS` is how many independent sequences Rapid generates.
`EXPLORATORY_STEPS` is the average number of state-machine actions per
sequence.

The draw is deterministic. The wall clock is not: envtest, informers, and
in-flight HTTP can still make Rapid report `flaky test, can not reproduce a
failure`. Record the seed and the failfile anyway.

## CI

PR CI runs `make test-exploratory-compile` only. It does not execute the
random state machines.

`.github/workflows/exploratory.yaml` runs `make test-exploratory` on a
nightly schedule and on `workflow_dispatch`. Dispatch requires seed, checks,
and steps (defaults `1`, `25`, `8`). A scheduled run with an empty seed uses
the UTC unix timestamp, so each night explores a new stream. The job allows
75 minutes. On failure it uploads `bin/exploratory-artifacts` for 14 days.

## Reproducing a failure

The test log prints a `-rapid.seed=` and often a `-rapid.failfile=` path.
Replay with the same binary flags Rapid printed. Do not replay a stale
failfile from an earlier binary or oracle; Rapid then reports that the
failfile is no longer valid.

Traces under `EXPLORATORY_ARTIFACT_DIR` (default `bin/exploratory-artifacts`)
project free-form identifiers. They are for diagnosis, not a substitute for
the failfile.

## After a real counterexample

1. Keep the seed and the minimized sequence.
2. Write a unit or envtest case that fails on the same contract.
3. Fix the controller or the oracle, whichever the evidence supports.
4. Drop the Rapid failfile from the tree. Do not commit `testdata/rapid/`
   leftovers; this is a public repository.
