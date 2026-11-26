# Changelog

## Unreleased

## v0.5.0 - 2026-11-26

### Changed

- Tighten `DeviceSettings` and `ZeroTrustOrganization` `spec.deletionPolicy` from `DeletionPolicy` to `OrphanOnlyDeletionPolicy` (`Enum=Orphan`) in `api/v1alpha1` and CRD admission (#185); see [the upgrade guide](docs/operations/upgrade.md) to remove legacy `deletionPolicy: Delete` values before restoring manifests.
- Reject negative and sub-second `GatewayOriginRequestSpec` durations (`connectTimeout`, `keepAliveTimeout`, `tcpKeepAlive`) at CRD admission via CEL on `GatewayClassConfig` and `CloudflareTunnel` (#182).

### Fixed

- Demote `CloudflareTunnel` `ConfigApplied=False` (`ConfigurationError`) and `Gateway`/`Listener` `Programmed=False` (`Invalid`) if runtime `cloudflared` configuration compilation fails on `GatewayOriginRequestSpec` (#182).
- Prevent invalid top-level `Gateway` specs (`Accepted=False` on `spec.addresses`, `spec.allowedListeners`, or `spec.tls`) from auto-creating a default `CloudflareTunnel` or overwriting `Programmed` `Invalid` with a requeuing `Pending` status (#186).
- Retain verified DNS ownership authorization across `Gateway` detachment, `Gateway -> Direct` switches, and deletion when a `CloudflareTunnel` previously created DNS records under a differently named `Gateway` (#187).
- Roll back the pending `ServiceToken` create journal, empty reserved destination
  Secret, and attempt finalizer when `CreateServiceToken` fails with a
  definite non-creation HTTP `4xx` error (excluding `408`, `409`, and `429`),
  preventing objects from wedging in `RecoveryPending` or `CleanupBlocked` (#181).
- Isolate per-zone listing failures (HTTP `403`, `404`, `5xx`, and transport
  errors) in zone-scoped Access sweeps (`AccessApplication`,
  `AccessStandaloneApplication`, `AccessGroup`, `ServiceToken`) so account-scoped
  and permitted-zone drift detection continue cleanly (#183).
- Bind each `ClusterLoadAssignment` (`EndpointType`) Delta xDS version to its
  owning `Cluster` version in `translator.Build`, eliminating the 15s Envoy EDS
  warming stall and temporary stale-SAN window when `BackendTLSPolicy` or
  cluster settings update without endpoint IP changes (#180).
- Guard optional CRD CEL fields with `has(...)` before calling `size(...)` or
  dereferencing optional booleans on
  `CloudflareTunnelIngressRule.originRequest.ipRules`,
  `DevicePostureRule.input.certificateId`,
  `DevicePostureIntegration.config.{apiUrl,authUrl,clientId,customerId}`, and
  `DeviceProfile.spec.splitTunnel.routeSources.privateHostnameRange` (#184).
- Isolate Access block-first transitions, listener DNS readiness, and private
  routing prerequisites per listener or protection domain while keeping
  persisted public Envoy ports sticky across listener additions, removals, and
  upgrades:
  - Keep `(listener, protectionDomain) -> envoyPort` bindings sticky across
    reconciles and upgrades, and assign deterministic unused hash ports to new
    domains instead of shifting unrelated listeners' ports.
  - Record `CloudflareTunnel.status.hostnames[].accessBinding` digests and run a
    one-time fail-closed `AccessTransition` (`403`) checkpoint for legacy
    protected hostnames lacking `accessBinding` on upgrade, then resume
    forwarding once converged.
  - Model domain blocking with explicit `BlockReason` states so Access
    block-first transitions, unready Access applications, and revocation holds
    keep only the affected listeners and Gateway `Programmed=False` (`Pending`)
    until forwarding resumes, while leaving independent listeners and domains
    forwarding.
  - Restore the 30s convergence timeout when `ConfigApplied=True` and replace
    steady 2s polling with bounded timeout/freshness requeues after
    convergence or timeout.
  - Normalize managed DNS hostnames consistently across DNS readiness checks
    and listener status computation.
  - Ignore synthetic conflict-only `status.dnsRecords[]` entries (empty
    `recordId`) during `CloudflareTunnel` deletion (`Delete` and `Orphan`),
    preventing deletion deadlocks.
  - Preserve `PrivateListenerDegraded=True` (`PodIPFallback`) whenever an
    active private listener uses PodIP fallback while a sibling listener is
    pending, and prefer non-deleting `Applied` `HostnameRoute` objects.
  - Separate the Gateway config freshness gate key (`"CloudflareTunnelConfig"`)
    from the tunnel/DNS drift sweep key (`"CloudflareTunnel"`) (#135).

## v0.4.1 - 2026-11-22

### Fixed

- Close half-open xDS streams faster and prevent stale Envoy dataplane routing
  by enabling client-side HTTP/2 `connection_keepalive` (`30s` interval, `5s`
  timeout, `30s` idle interval) in Envoy bootstrap, lowering xDS server
  `KeepaliveEnforcementPolicy.MinTime` to `15s`, enforcing `node.id`
  immutability on ADS streams, and waking the Gateway controller immediately on
  stream closure.
- Require xDS ACK convergence per active non-terminating dataplane Pod UID
  across `cloudflareGate`, `ConformanceMode`, teardown deny gates (excluding
  unscheduled `Pending` Pods without an IP), and `gatewayPromotionGuard`, and
  avoid reporting false 30s timeouts on immediate post-convergence disconnects
  (#175).

## v0.4.0 - 2026-11-08

### Fixed

- Scope periodic drift-sweep targets and remote list calls to enabled controller
  groups, preserving Gateway DNS and Tunnel checks without requiring permissions
  for disabled features (#163).

- Reject `Gateway.spec.tls` and `Gateway.spec.listeners[].filters` with
  fail-closed status conditions, preserve foreign Gateway status conditions,
  and handle 253-character Gateway and Tunnel names.

### Changed

- Upgrade the Go toolchain to 1.27.3 and refresh Go modules, including the
  Cloudflare SDK v7.13.1 and Envoy API v1.40.0.
- Update build tools and pinned builder images, including controller-tools
  v0.23.0, golangci-lint v2.15.0, cosign v3.1.4, and Helm v4.3.1. Move the
  Go builder and devcontainer base to Debian 13 (`trixie`).
- Update data-plane and test images to cloudflared `2026.10.2`, Envoy
  `distroless-v1.40.0`, CoreDNS `1.15.0`, and agnhost `2.61`.
- Update site dependencies to Bun 1.4.3, Astro 7.4.1, Astro check 0.9.11,
  and Bun types 1.4.3. Retain TypeScript 6.0.3 as the approved compatibility
  exception: Astro check 0.9.11 supports TypeScript 5/6, not 7.
- Use formatter-safe empty string literals in the scheduling CEL markers,
  preserving the existing validation rules when Go formats the source.
- Keep Gateway envtest status writes bounded while live controllers run:
  retry only resource-version conflicts and fail immediately on other errors.

- Upgrade Gateway API to v1.7.0. Controllers remain backward-compatible with
  Gateway API v1.6.x Standard CRDs for v1.6.x resources and fields.
- Add support for `HTTPRouteRetryCodes`, `HTTPRouteRetryConnectionError`,
  `HTTPRouteBackendURLRewrite`,
  `HTTPRouteBackendRequestHeaderModification`, `HTTPRouteNamedRouteRule`, and
  `GatewayRouteHostnameIntersectionPrecedence`.

## v0.3.3 - 2026-10-11

### Changed

- Bump the default data-plane images to cloudflared `2026.10.0` and Envoy
  `distroless-v1.39.3`, and build with Go 1.27.2.
- Target Gateway API v1.6.3. The supported feature published in
  `GatewayClass.status.supportedFeatures` as `GatewayInfrastructurePropagation`
  is now `GatewayInfrastructure`, the name Gateway API v1.6.3 uses for it. The
  conformance report moved to `docs/conformance/v1.6.3/`.
- Update Go modules (including cloudflare-go v7.12.0, controller-runtime
  v0.25.2, and Kubernetes v0.37.1), build tools (golangci-lint v2.14.0,
  kustomize v5.8.3, cloud-provider-kind v0.12.0, cosign v3.1.3, envtest and
  Kind node v1.37.0), GitHub Actions, and site dependencies. Release images
  keep the same cosign signature format as earlier releases.

### Fixed

- Keep a host that a revoked AccessApplication's tombstone still blocks
  blocked until the revocation is acknowledged. A public host is held on every
  public listener of the tunnel, a private host on its own listener, and a
  wildcard host together with every host under it. Another AccessApplication
  claiming a held host stays accepted, but its domain for that host is held
  Blocked and its status names the revoked application. A route left on a
  listener that permits unprotected traffic no longer serves the host ahead of
  the tombstone's block, and a private TLS listener for that host no longer
  fails the Gateway xDS snapshot with a duplicate SNI filter chain (#143).
- Shadow a protected exact host at any subdomain depth inside a covering
  wildcard's Envoy route table, matching how the edge routes it.
- Serve every host of a private TLS listener from one SNI filter chain, with
  each host enforcing its own guard: a blocked host answers 403 and is never
  forwarded, and each Access host requires its own application's JWT. A
  private wildcard listener whose hosts mix guards, such as the listener's
  own blocked wildcard host next to an Access host, two AccessApplications
  with different AUDs, or an Access host whose AUD is not ready yet, no
  longer fails the Gateway xDS snapshot with a duplicate SNI filter chain
  (#145).
- Stop a CloudflareTunnel with a standing conflict, such as a DNS record it
  does not own or an adoption mismatch, from reconciling in a tight loop. Each
  pass cleared `Conflict` or promoted `Accepted` before reading Cloudflare,
  then reverted them afterwards. The two status writes re-queued the Tunnel
  through its own watch and kept spending Cloudflare API budget. Both now
  change only after the remote reads confirm no conflict.
- A NetworkRoute or HostnameRoute no longer records another writer's change
  as `status.applied` or reports Ready when the route changed between the
  controller's update and its read-back. The pass reports `CloudflareError`
  and retries.

## v0.3.2 - 2026-10-08

### Fixed

- Preserve Envoy's initial resource-version proof when it reconnects before
  the first controller snapshot, allowing Gateway xDS convergence after a
  controller restart without restarting Envoy.
- Keep a revoked AccessApplication's blocked tombstone on the Envoy port the
  applied tunnel config still routes to, and allocate live public listener and
  Access host ports around it. Deleting the last route on an Access-protected
  listener no longer fails the Gateway xDS snapshot with a duplicate bind
  (#141). Bind-collision errors now name both protection domains and say
  "cleartext" when neither side uses TLS.
