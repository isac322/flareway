# Changelog

## Unreleased

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

- Preserve Envoy's initial resource-version proof when it reconnects before
  the first controller snapshot, allowing Gateway xDS convergence after a
  controller restart without restarting Envoy.
- Keep a revoked AccessApplication's blocked tombstone on the Envoy port the
  applied tunnel config still routes to, and allocate live public listener and
  Access host ports around it. Deleting the last route on an Access-protected
  listener no longer fails the Gateway xDS snapshot with a duplicate bind
  (#141). Bind-collision errors now name both protection domains and say
  "cleartext" when neither side uses TLS.
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
