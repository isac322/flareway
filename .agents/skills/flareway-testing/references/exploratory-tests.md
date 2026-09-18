# Exploratory tests

Apply `rule://flareway-invariants`. This note describes the suite under
`test/exploratory` (`//go:build exploratory`). How to schedule and replay it
is in `exploratory-operations.md`.

## What it is

The suite is Rapid state-machine testing of the real reconcilers. It is not
byte-level fuzzing and not live Cloudflare e2e.

`pgregory.net/rapid` generates sequences of typed actions (create an account,
revoke a grant, inject a 429, restart the manager). After every action the
machine waits for quiescence and checks family invariants against Kubernetes
status, the Cloudflare stub journal, and stub remote state.

The control plane is envtest (real API server and etcd). Cloudflare is
`test/cfstub`. Envoy is a test snapshot publisher, not a running proxy. No
Kind cluster and no Cloudflare account are involved.

A fixed seed replays one generated integration path. Changing the seed
changes which action sequences Rapid draws, and therefore which object
combinations appear.

## Layout

| Test | Role |
|---|---|
| `TestAccessStateMachine` | Account grants, AccessPolicy, AccessApplication, ServiceToken, faults, restarts |
| `TestGatewayStateMachine` | GatewayClass/Gateway, implicit and explicit tunnels, DNS/config writes, ACK/NACK, grant denial |
| `TestNetworkRouteStateMachine` | VirtualNetwork, NetworkRoute, Direct-mode tunnels, ObserveOnly seeds, remote drift, deletion residue |
| `TestSmokeAccountVerificationRoundTrip` | Fixed, non-Rapid smoke: account verification through the production SDK against cfstub, including retry exhaustion and a manager restart |

`make test-exploratory` compiles with `-race` and runs those four tests in
separate processes so one family's timeout cannot swallow another.

## Harness

`explorationHarness` starts envtest with Flareway and Gateway API CRDs, starts
cfstub, points `flarecloudflare.DefaultFactory` at the stub URL, and registers
the controller set used by these families. Each Rapid check iteration resets
stub state and uses fresh Kubernetes names.

`waitStable` polls caller expectations plus the stub journal. It also counts
Cloudflare HTTP calls the production client has started but not finished, so
a drain does not return while a request is still in flight.

Traces persist HMAC-projected identifiers and Secret metadata (existence, key
count, total bytes), not Secret values.

## What each Check asserts

Access (`Check` in `access_state_machine_test.go`):

- No new Access provisioning (POST/PUT/PATCH) after the denial watermark.
  GET/DELETE may finish cleanup that already passed the grant gate.
- An application is not `Programmed` under policy uncertainty or a latched
  revocation; this family does not publish AUD Secrets.
- ServiceToken one-time credentials are captured before Ready.
- ObserveOnly objects cause no remote mutations.

Gateway (`Check` in `gateway_state_machine_test.go`):

- Token verification precedes account-scoped calls; tunnel create precedes
  tunnel-scoped calls.
- No new remote object is provisioned while the account is unverified or the
  bound tunnel is unauthorized. Updates of an already-owned DNS record or
  tunnel configuration may complete after revocation.
- One writer owns tunnel configuration per mode; drain precedes a handoff.
- `Programmed` requires the family's convergence gates (xDS ACK, desired
  config, DNS except `dns.mode: External`).
- After hostname grant denial, Gateway listeners that exist report
  `Accepted=False`, and no later POST republishes those hostnames.

Network (`Check` in `network_state_machine_test.go`):

- Unauthorized accounts do not receive new remote writes.
- ObserveOnly seeds stay byte-identical on the stub.
- Deletion residue matches Delete versus Orphan.
- Applied status converges for managed objects that still have a granted
  account.
- `RemoteDrift` only targets managed objects whose account still exists and
  is granted.

These checks apply the Flareway invariants; they do not redefine them.

## What it cannot prove

It cannot prove Cloudflare edge HTTP, live DNS, Access challenge pages, or
WARP. It cannot prove Envoy data-plane traffic. A passing seed does not prove
every sequence Rapid could draw. Rapid reporting `flaky test, can not
reproduce a failure` means the draw replayed but the timing did not.
