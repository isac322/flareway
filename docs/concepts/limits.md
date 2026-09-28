# Limits and boundaries

Flareway refuses configuration it cannot serve and reports why in status. This page lists each boundary, how it is refused, and the timing limits.

Most boundaries appear as a condition on the object you applied, with a reason and a message. The rest are timing properties and Cloudflare edge limits that no status condition can show.

## Controller

The controller runs as one replica with leader election enabled, and Gateways are reconciled by one worker, one at a time. The chart's controller Deployment uses the `Recreate` strategy. The `cloudflared` connector is separate: each tunnel runs two connector replicas by default (`connector.replicas` in the Gateway class configuration).

## Gateway API scope

Flareway implements `HTTPRoute`. `GRPCRoute`, `TLSRoute`, `TCPRoute`, and `UDPRoute` are not implemented. A listener whose `allowedRoutes.kinds` names any kind other than `HTTPRoute` reports `ResolvedRefs=False` with reason `InvalidRouteKinds`. To reach private TCP services, use a `NetworkRoute` or a [Direct tunnel](../get-started/direct-tunnels.md).

The controller does not claim these Gateway API features in `GatewayClass.status.supportedFeatures`:

- `GatewayAddressEmpty`
- `GatewayBackendClientCertificate`
- `GatewayFrontendClientCertificateValidation`
- `GatewayFrontendClientCertificateValidationInsecureFallback`
- `GatewayPort8080`
- `GatewayStaticAddresses`
- `HTTPRouteBackendRequestHeaderModification`
- `HTTPRouteNamedRouteRule`
- `HTTPRouteRetry`
- `HTTPRouteRetryBackendTimeout`
- `HTTPRouteRetryConnectionError`
- `ListenerSet`

Some of these are refused with a specific reason:

| Configuration | Result |
|---|---|
| `Gateway.spec.addresses` set, with or without a value (`GatewayStaticAddresses`, `GatewayAddressEmpty`) | `Accepted=False`, reason `UnsupportedAddress`. Cloudflare owns the edge addresses. A Gateway with a public listener reports the tunnel's `<tunnel-id>.cfargotunnel.com` hostname as its address. |
| `Gateway.spec.allowedListeners` set (`ListenerSet`) | `Accepted=False`, reason `ListenersNotValid`. |
| An `ExtensionRef` filter on a rule | The rule is invalid with reason `InvalidKind`. Flareway defines no extension filter kinds. |
| A `backendRef` to anything other than a core `Service` | Reason `InvalidKind`. An `ExternalName` Service is treated as not found. |

[HTTPRoute routing](http-routing.md) lists the supported features and what each unsupported one does to a route.

## Public listeners

A public listener is served by Cloudflare's edge, so it follows the edge's rules:

- Only `HTTP` on port 80 and `HTTPS` on port 443. Another port reports reason `PortUnavailable`; another protocol, including `TLS` passthrough, reports reason `UnsupportedProtocol`.
- Every listener needs a `hostname`, and the hostname must be granted to the namespace by the `CloudflareAccount`.
- Cloudflare terminates TLS at the edge. A listener that sets `certificateRefs` is rejected with the message `edge-terminated listener must not reference certificates`. The only accepted TLS option is `flareway.bhyoo.com/edge-tls-mode`, set to `Full` or `Strict`.
- One hostname cannot be both public and private on the same Gateway. The `CloudflareTunnel` reports `hostname exposure must be unique per Gateway`; use separate hostnames.
- Cloudflare Universal SSL covers the zone apex and one level of subdomain. A hostname deeper than that, such as `a.b.example.com`, needs an edge certificate from Cloudflare Advanced Certificate Manager, which Flareway does not provision. A grant wildcard such as `*.example.com` also matches exactly one label.
- `HTTPRoute` redirects to a port other than 80 or 443 on a public hostname are compiled, but Cloudflare's edge does not serve that destination.

## Private listeners

A private listener is reached over WARP, and Envoy terminates TLS:

- Only `HTTPS`, on any port. Envoy listens on the listener's declared port, because Cloudflare forwards the original destination port.
- Exactly one `certificateRefs` entry, naming a Secret you supply. Flareway does not issue certificates; use cert-manager or an internal CA.
- The account and devices need WARP setup: `DeviceSettings` with `gatewayProxyEnabled` and `gatewayUdpProxyEnabled` set to `true`, a `HostnameRoute` or `NetworkRoute` to the tunnel, a device profile that includes the private hostname ranges when it uses Include mode, no overlap between a hostname route and a fallback DNS suffix, and a compatible WARP client and Cloudflare plan.
- Origin JWT verification on a private hostname requires Cloudflare Gateway TLS decryption, confirmed with `AccessApplication.spec.originJWT.assumeGatewayTLSDecryption: true`.

Not verified live: a CoreDNS sidecar answers private hostnames with `127.0.0.1` so that WARP traffic passes through Envoy. That behavior is measured locally, but no live Cloudflare edge and WARP run has confirmed that the edge accepts a `127.0.0.1` answer for a private hostname.

[Reach private Services over Cloudflare WARP](../get-started/private-services-over-warp.md) walks through the setup.

## Cloudflare edge limits and long streams

Cloudflare's own limits apply to every public hostname, whatever the origin allows. Cloudflare waits 100 seconds for response headers (Enterprise plans can raise this), caps request bodies by plan (100 MB on Free and Pro), and closes WebSockets idle for 100 seconds. Server-sent events must not be buffered.

For long streams, set `timeouts.request: 0s` on the `HTTPRoute` and raise `proxy.streamIdleTimeout` in the Gateway class configuration (the chart default is `1h`). These settings configure the origin data plane only. Long streams through the edge, such as a 150-second SSE stream or a response whose first byte arrives after 120 seconds, have not been measured live.

## Timing

Access revocation is bounded by token expiry. Cloudflare propagates a revoked session to its edge in about 20 to 30 seconds, but `cloudflared` and Envoy validate Access JWTs without calling Cloudflare, so a signed token stays valid at the origin until its `exp` time.

Out-of-band edits are detected after a delay. Changes made through Kubernetes apply at once. Edits made in the Cloudflare dashboard or by another tool are found by a periodic sweep. Its default intervals are 60 seconds for Access objects, 5 minutes for tunnels, DNS, and private routes, and 30 minutes for device and organization settings. Between completed passes the sweep waits the interval plus up to 20% jitter, and sweep duration, rate limiting, and API failures can delay detection further, so treat these as polling intervals rather than deadlines. The Helm chart sets the intervals with its `reconcile.freshness` values.

Cloudflare API calls share a fixed budget. Reconcilers use 3.5 requests per second and the drift sweep uses 0.5, which keeps both inside Cloudflare's account limit of 4.0 requests per second.

[Drift detection and Cloudflare API budget](../operations/freshness-and-drift.md) explains the freshness grades and how to tune them.

## API and support

The API version is `flareway.bhyoo.com/v1alpha1`. Only the most recent release receives fixes; there is no long-term support line and no backport policy. See the [security policy](../SECURITY.md) for how to report a vulnerability.

Next: [Install Flareway](../get-started/install.md).
