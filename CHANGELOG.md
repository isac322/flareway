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
