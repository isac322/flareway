# Changelog

## Unreleased

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
  blocked on its listener until the revocation is acknowledged. Another
  AccessApplication claiming the host stays accepted, but its domain for that
  host is held Blocked and its status names the revoked application; a route
  left on a listener that permits unprotected traffic no longer serves the
  host ahead of the tombstone's block. A private TLS listener for that host no
  longer fails the Gateway xDS snapshot with a duplicate SNI filter chain
  (#143).
