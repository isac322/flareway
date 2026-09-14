# Flareway

Flareway is a Kubernetes operator that implements Gateway API traffic management on Cloudflare Tunnel, Access, and WARP with an Envoy data plane.

The project targets the Gateway API `GatewayHTTP` profile first. Kubernetes Ingress support may follow after the Gateway API implementation is complete.

Flareway is pre-implementation and experimental. Do not treat it as production-ready until the official Gateway API conformance suite and Cloudflare edge end-to-end tests pass. See the [design document](docs/design/001-cloudflare-gateway-api-integration.md) for the planned architecture and security model.

## License

Copyright 2026 Byeonghoon Yoo. Licensed under the Apache License 2.0; see [LICENSE](LICENSE).
