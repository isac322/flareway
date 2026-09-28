# Flareway: Gateway API on Cloudflare Tunnel

![Flareway logo: an orange cloud with a doorway beside the Flareway wordmark](assets/cloud-gateway/d2/logo-t3.svg)

Flareway turns a Kubernetes `Gateway` into a Cloudflare Tunnel, runs `HTTPRoute` rules in Envoy, and verifies Access at the origin, with no inbound ports.

## The problem

Cloudflare Tunnel exposes a cluster without inbound firewall ports or public
IPs: `cloudflared` dials out to Cloudflare's edge and carries requests back.
On its own, `cloudflared` routes only by hostname and an unanchored path
regex. Its ingress rules cannot match methods, headers, or query parameters,
and they cannot rewrite, redirect, mirror, or split traffic by weight.

## Why Flareway

- **Full HTTPRoute routing behind the tunnel.** Method, header, and query
  matches, rewrites, redirects, mirroring, timeouts, CORS, and weighted splits
  work through the tunnel without a second proxy for you to run.
  [HTTP routing](docs/concepts/http-routing.md)
- **Access enforced at the edge and origin.** Attach an `AccessApplication` to
  a listener or route: Flareway creates the Cloudflare Access application and
  policy, then verifies the Access JWT again inside the cluster, so a request
  that did not pass Access is refused at the origin. You never copy an AUD tag
  by hand. [Security model](docs/concepts/security-model.md)
- **Private services over WARP, same Gateway.** Mark a listener `Private` and
  WARP devices reach the Service through the same `Gateway`, `HTTPRoute`, and
  `AccessApplication`, with Envoy terminating TLS using your certificate.
  Virtual networks, routes, and WARP connectors are Kubernetes resources.
  Whether the Cloudflare edge accepts the `127.0.0.1` answer for private
  hostnames has not been verified live; see [Limits](docs/concepts/limits.md).
  [Private services over WARP](docs/get-started/private-services-over-warp.md)
- **Fails closed on shared clusters.** A namespace can use only the
  hostnames, zones, and exposures the platform granted it. Deleting a policy
  never makes a protected route public, existing Cloudflare objects are never
  taken over by name, and `Programmed` means traffic has converged.
  [Security model](docs/concepts/security-model.md)

The routing features Flareway claims passed the Gateway API conformance suite
in a local run through Envoy; the
[conformance report](conformance/reports/v1.6.2/flareway/README.md) states what
that run covered.

## How it works

Each `Gateway` gets one `CloudflareTunnel` and one data-plane Deployment. The
Gateway names its tunnel through the standard `infrastructure.parametersRef`,
with no annotations.

- `cloudflared` dials out to Cloudflare's edge over QUIC or HTTP/2 and forwards
  each hostname to Envoy over loopback. It carries transport only.
- Envoy runs the `HTTPRoute` rules that the controller streams to it over xDS
  (Delta ADS).
- For a Gateway with private listeners, a CoreDNS sidecar answers private
  hostnames with `127.0.0.1`, so WARP traffic also passes through Envoy.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/architecture/layers-dark.svg">
  <img src="assets/architecture/layers-light.svg" alt="Four layers: Internet and WARP clients, the Cloudflare edge with edge TLS and private network routes, an outbound tunnel through a sealed cluster boundary while inbound is blocked, and the Kubernetes data-plane pod feeding Services and backend Pods">
</picture>

[How Flareway works](docs/concepts/how-it-works.md) covers listeners, TLS,
Access, Direct mode, and the full object map.

## Try it without a cluster

Rendering the published chart needs no cluster and no Cloudflare credentials.
You need Helm 4.3 or a compatible Helm 3 client.

```sh
helm template flareway oci://ghcr.io/isac322/charts/flareway \
  --namespace flareway-system \
  --set gatewayClass.create=true
```

The output contains the controller Deployment, RBAC, Services, and
NetworkPolicies, plus `GatewayClass/flareway` and `GatewayClassConfig/default`
because of `gatewayClass.create=true`. Add `--include-crds` to also render the
Flareway CRDs. `gatewayClass.create` defaults to `false` so that an install
cannot take ownership of an existing `GatewayClass`.

## Start here

You need a Kubernetes cluster with the Gateway API v1.6.2 Standard CRDs, Helm,
a Cloudflare account with a scoped API token, and a DNS zone in that account
for public hostnames. Then follow the guides in order:

1. [Install](docs/get-started/install.md)
2. [Connect Cloudflare](docs/get-started/connect-cloudflare.md)
3. [Expose a Service](docs/get-started/expose-a-service.md)

## When it fits, and when it doesn't

Flareway fits when you want standard `Gateway` and `HTTPRoute` resources in
front of Cloudflare Tunnel, Access policies declared next to the routes they
protect, private services over WARP, or several namespaces sharing one
Cloudflare account under explicit grants.

Check these boundaries first:

- The controller runs as one replica with leader election.
- `HTTPRoute` is the only route kind. A listener whose `allowedRoutes.kinds`
  names `GRPCRoute`, `TLSRoute`, `TCPRoute`, or `UDPRoute` reports
  `ResolvedRefs=False` with reason `InvalidRouteKinds`. For TCP, SSH, or RDP
  origins, use a [Direct tunnel](docs/get-started/direct-tunnels.md).
- Some Gateway API features are not supported, including `HTTPRouteRetry`,
  `ListenerSet`, `GatewayStaticAddresses`, and
  `HTTPRouteBackendRequestHeaderModification`.
- Cloudflare's edge limits still apply: it waits 100 seconds for response
  headers (up to 6,000 on Enterprise), caps request bodies by plan, and closes
  WebSockets after 100 seconds idle. It does not serve redirects to ports
  other than 80 and 443 on public hostnames.

[Limits](docs/concepts/limits.md) lists every boundary and what is not yet
verified.

## Documentation

- **Concepts:** [How it works](docs/concepts/how-it-works.md),
  [HTTP routing](docs/concepts/http-routing.md),
  [Conformance report](conformance/reports/v1.6.2/flareway/README.md),
  [Security model](docs/concepts/security-model.md),
  [Ownership and adoption](docs/concepts/ownership-and-adoption.md),
  [Limits](docs/concepts/limits.md)
- **Get started:** [Install](docs/get-started/install.md),
  [Connect Cloudflare](docs/get-started/connect-cloudflare.md),
  [Expose a Service](docs/get-started/expose-a-service.md),
  [Protect with Access](docs/get-started/protect-with-access.md),
  [Private services over WARP](docs/get-started/private-services-over-warp.md),
  [Direct tunnels](docs/get-started/direct-tunnels.md)
- **Operations:** [Troubleshooting](docs/operations/troubleshooting.md),
  [Upgrade](docs/operations/upgrade.md),
  [Drift and API budget](docs/operations/freshness-and-drift.md)
- **Reference:** [API reference](docs/api-reference.md),
  [Helm chart values](charts/flareway/README.md),
  [kubectl explain](docs/api/README.md),
  [example manifests](config/samples/)
- **Project:** [Contributing](CONTRIBUTING.md),
  [Security policy](SECURITY.md),
  [Code of conduct](CODE_OF_CONDUCT.md),
  [design documents (Korean)](docs/design/001-cloudflare-gateway-api-integration.md)

Next: [How Flareway works](docs/concepts/how-it-works.md).

## License

Copyright 2026 Byeonghoon Yoo. Licensed under the Apache License, Version 2.0.
See [LICENSE](LICENSE) for details.
