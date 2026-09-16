# Data plane and xDS convergence

How a `Gateway` becomes programmed: the cloudflared remote configuration,
the per-Pod probes, and the Envoy Delta xDS ACK gate. Apply
`rule://flareway-invariants`; Access guard and credential rules live in
`skill://flareway-security`.

## Roles

- **GatewayReconciler** (`internal/controller/gateway_controller.go`,
  `gateway_cloudflare.go`, `gateway_private.go`): collects inputs, runs
  `gatewayapi.Translate` into `ir.Gateway`, builds the xDS snapshot, writes
  the remote cloudflared configuration, reconciles the dataplane resources,
  and gates `Programmed`.
- **cloudflared** (connector container): runs `tunnel run` with
  `TUNNEL_TOKEN` from the controller-owned Secret. It receives its whole
  ingress configuration remotely — the controller writes it via the
  Cloudflare API, never a mounted config file. Exposes `:2000` with
  `/ready` (readiness), `/healthcheck` (liveness), `/metrics`, and `/config`
  (reports the orchestration config version it is running).
- **Envoy**: connects to the leader-elected Delta ADS server
  (`flareway-xds.<operator-ns>.svc.cluster.local:18000`) over mTLS with a
  per-Gateway client certificate. Node identity is `cluster =
  "namespace/name"`; `--service-node` carries the Pod identity. Admin is
  loopback-only on `127.0.0.1:19000`; a static health listener answers
  `/healthz` on `:19001`.
- **dns sidecar** (private listeners only): pod-local CoreDNS answering
  private hostnames; cloudflared is pointed at `127.0.0.1:53` via
  `TUNNEL_DNS_RESOLVER_ADDRS`.

`internal/dataplane/` builds the Deployment (cloudflared + envoy [+ dns]),
bootstrap ConfigMap, Service, PDB, NetworkPolicy, and the private-DNS
ConfigMap. The bootstrap ConfigMap hash lands in the
`flareway.bhyoo.com/config-hash` label/annotation so bootstrap changes roll
the Pods.

## Delta xDS and the AckTracker

`internal/xds/server` serves Delta ADS only (LDS, RDS, CDS, EDS, SDS). The
server requires `NeedLeaderElection` — only the elected manager replica
serves, matching the single-writer snapshot contract. mTLS is mandatory:
`pki.ServerTLSConfig` requires and verifies client certs, and a stream
interceptor authorizes the SPIFFE URI SAN
(`spiffe://flareway.bhyoo.com/ns/<ns>/gateway/<name>`) against the node
cluster the stream claims.

`SetSnapshot(node, snapshot)` validates consistency, builds the Delta
version map, computes one version plus a per-type fingerprint of the
resource version map, records `ExpectSnapshot`, then publishes to the
cache. `ClearSnapshot` drops the snapshot and convergence state.

`AckTracker` (`tracker.go`) semantics — read these before "fixing" a stuck
ACK:

- `ExpectSnapshot` records only types whose resource fingerprint changed.
  Unchanged types emit no Delta response and never block convergence;
  removed types do not block either.
- `OnResponse` binds the response nonce to the stream and proves the stream
  subscribes to that type. `OnRequest` consumes ACK/NACK by nonce and
  records type subscriptions; subscription-only requests (no nonce) just
  mark the type subscribed.
- **Reconnect initial versions**: a reconnected client that reports
  `initial_resource_versions` matching the current versions gets those
  types accepted without a response — the cache emits nothing in that case,
  so initial versions are the only protocol evidence of convergence.
- `OnStreamClosed` forgets that stream's nonces and subscriptions; a changed
  type stops blocking once no remaining stream subscribes to it.
- `Forget(node)` drops convergence records but keeps live stream identity —
  Delta requests carry `Node` only on the first request of a stream.
- `IsACKed(node, version)` is true only when every changed type that at
  least one live stream subscribes to has ACKed the exact version. An empty
  expected set converges immediately; a non-empty set requires a live
  stream, so a dead Envoy cannot converge vacuously.
- `ConvergenceDetails`/`ACKDetails` explains the wait (which type, which
  version); `LastNACK` returns the latest rejection detail.

## The Cloudflare programming gate

`cloudflareGate` must pass before `Programmed=True` and before
`configVersion.applied` advances. In order:

1. `validateGatewayTunnelWriter` — the Gateway still holds UID-bound
   ownership of a verified, non-deleted tunnel.
2. Remote config version parses and is non-zero.
3. Every active dataplane Pod (label `gateway.networking.k8s.io/gateway-name`)
   answers `/ready` with 200 **and** `/config` with the desired version.
   Terminating/failed Pods are skipped; a Pod with no IP, a failed probe, or
   a stale version is listed by name in the gate message.
4. `Snapshots.IsACKed(gatewayKey, snapshotVersion)` — the Envoy ACK gate,
   annotated with `ACKDetails` when available.
5. Managed DNS: every public listener hostname appears in
   `status.dnsRecords` (skipped entirely for `dns.mode: External`).
6. Private prerequisites (`reconcilePrivatePrerequisites`): verified tunnel
   + account, `DeviceSettings` `gatewayProxyEnabled` and
   `gatewayUdpProxyEnabled`, a ready `VirtualNetwork` per private listener,
   a ready `HostnameRoute`, and the origin-JWT TLS-decryption contract. Any
   miss blocks the private domains and adds a `Pending` message.

When the gate fails, `Programmed=False`/`Pending` lists the lagging items;
after the convergence timeout the message switches to "Timed out". Only a
fully ready gate (or a teardown deny snapshot that Envoy ACKed) sets
`ConfigApplied=True`/`Applied` and stamps `hostnames[].appliedVersion`.

## Block-first handoff

`accessBlockFirstGateway` makes protection transitions fail-closed. When the
desired config hash differs from `status.configVersion.desiredHash` and a
protected domain currently recorded as `Forwarding` — or a hostname with an
`Unprotected` entry — would forward under the new config, the reconciler
first publishes a variant with every protected domain forced to `Blocked`.
Only after that blocked config is applied (`hostnames[].guard=Blocked` at
the new `appliedVersion`) does the real config roll out. A hostname already
`Blocked` for the same protection domain is not re-blocked by a public
carve-out on the same name.

Debugging a stuck handoff:

1. Compare `status.configVersion.desiredHash` with the compiled hash —
   if they differ and guards are mid-transition, the blocked variant is in
   flight; check `ConfigApplied` and `hostnames[].guard`/`appliedVersion`.
2. If `ConfigApplied=False`/`Pending`, run the gate diagnostics below — the
   blocked config converges through the same probe/ACK/DNS path.
3. During teardown (`flareway.bhyoo.com/teardown`), all hostnames are forced
   `Blocked`; the tunnel finalizer waits for that before DNS removal.
4. Never force `guard` fields or delete the tunnel to unstick a handoff —
   find which gate item lags.

## Probe and snapshot convergence diagnostics

Work this list top to bottom; each step names the actual check the
controller performs:

```sh
kubectl describe gateway -n <ns> <name>          # Programmed message lists lagging items
kubectl describe cloudflaretunnel -n <ns> <tunnel>
kubectl get deploy,pods -n <ns> -l gateway.networking.k8s.io/gateway-name=<name>
```

1. **Pods**: every active Pod Ready; `kubectl logs <pod> -c cloudflared`
   for tunnel errors, `-c envoy` for xDS errors.
2. **cloudflared version**: `kubectl exec <pod> -c cloudflared -- wget -qO-
   localhost:2000/config` (or the metrics port) — the reported config
   version must equal `status.configVersion.desired`. A stale version means
   the connector has not pulled the new remote config; check its logs and
   edge connectivity.
3. **xDS ACK**: `Programmed` message shows `Envoy xDS ACK (...)` with the
   tracker detail — which type URL and version is unacknowledged. Check
   `LastNACK` detail in the same message path, then `kubectl logs` the
   manager for the xDS server and the envoy container for NACK reasons.
4. **No stream at all**: verify the xDS client Secret exists
   (`flareway-xds-<gateway>`), the bootstrap ConfigMap is mounted, and the
   envoy container reached the ADS address — mTLS or SAN failures show up
   as gRPC errors in envoy logs, not as NACKs.
5. **DNS**: compare public listener hostnames against
   `status.dnsRecords`; a missing record or `DNSReady=False`/`Conflict`
   means the tunnel controller has not finished (or found a foreign record).
6. **Private listeners**: `PrivateListenerDegraded` and the gate's pending
   message name the missing prerequisite (DeviceSettings flags,
   VirtualNetwork, HostnameRoute, TLS-decryption contract).

## JWKS TLS/DNS diagnostics

Protected domains get an Envoy `jwt_authn` provider (`cloudflare-access`)
with `remote_jwks` pointing at `https://<auth-domain>/cdn-cgi/access/certs`
through a generated `flareway-jwks-<hash>` cluster: `STRICT_DNS`, IPv4-only
lookup, TLS 1.3 upstream context with SAN matching the auth domain. When
protected routes return 401/403 unexpectedly:

1. Confirm the JWKS cluster exists in the snapshot and is ACKed — a NACK on
   the cluster type blocks the whole gate.
2. From the envoy container, check cluster health via the loopback admin
   (`127.0.0.1:19000/clusters`) — `flareway-jwks-*` must have healthy
   endpoints; `STRICT_DNS` resolution failures mean Pod DNS cannot resolve
   the auth domain.
3. TLS failures (SAN mismatch, handshake) appear in envoy logs against the
   JWKS cluster; the SAN is pinned to the normalized auth domain, so a
   wrong `authDomain` value fails validation, not silently passes.
4. `jwt_authn` fails closed: no key, bad `aud`, or unreachable JWKS means
   denied requests, and `OriginJWTEnforced` on the `AccessApplication`
   reports the enforcement state. For private listeners the
   `assumeGatewayTLSDecryption` contract must be explicit before
   programming.
