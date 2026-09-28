# HTTPRoute routing behind Cloudflare Tunnel

`cloudflared` matches only hostname and path. Flareway runs `HTTPRoute` in Envoy for method, header, and query matches, rewrites, mirrors, and weighted splits.

## What `cloudflared` ingress rules can match

A `cloudflared` ingress rule has a hostname, an optional path, and a service. The hostname matches exactly or by wildcard suffix, and `*.example.com` also matches `a.b.example.com`. The path is an unanchored Go regular expression, so `path: /admin` matches `/admin`, `/v1/admin`, and `/administrator`. Rules are evaluated in order and the first match wins.

An ingress rule cannot match on method, header, or query parameter, and it cannot split traffic by weight, rewrite a path or host, redirect, change headers, or mirror a request. The origin receives the path the client sent.

## What Flareway does instead

Flareway uses `cloudflared` for transport and Envoy for routing. Both run in the Gateway's data-plane pod:

- The controller compiles each `Gateway` and its attached `HTTPRoute` objects into Envoy route tables and streams them to Envoy over xDS (Delta ADS).
- For each public hostname, Flareway writes a `cloudflared` ingress rule whose service is an Envoy port on loopback, `http://127.0.0.1:<port>`. Each protection domain gets its own port. When a hostname needs path rules, for example because Cloudflare Access protects only part of it, Flareway anchors each path: an `Exact` path `/admin` becomes `^/admin$`, and a `PathPrefix` path `/admin` becomes `^/admin(/|$)`.
- Envoy evaluates the `HTTPRoute` matches and filters and forwards the request to your Service.

`cloudflared`, Envoy, and CoreDNS run as the upstream images, pinned by digest in the Helm chart values. Flareway does not fork them.

When several rules could match a request, Envoy tries them in this order:

1. `Exact` path, then `RegularExpression` path, then `PathPrefix` path, with the longer prefix first.
2. A rule that matches a method, before one that does not.
3. More header matches, then more query parameter matches.
4. The older `HTTPRoute` by creation time, then `namespace/name`, then rule index, then match index.

Gateway API does not define where regular-expression paths rank against other path types, so Flareway fixes them between `Exact` and `PathPrefix`.

## Supported features

Flareway supports GatewayHTTP Core: `Gateway`, `HTTPRoute`, and `ReferenceGrant`. That includes `Exact` and `PathPrefix` path matches, exact header matches, request header modification, request redirects, and weighted `backendRefs`. Flareway also accepts `RegularExpression` for path, header, and query parameter matches.

The Extended features below are the ones Flareway claims in `GatewayClass.status.supportedFeatures`. Each name is a Gateway API feature name.

### Matching

| Feature | What it adds |
|---|---|
| `HTTPRouteMethodMatching` | Match on the HTTP method. |
| `HTTPRouteQueryParamMatching` | Match on query parameters. |
| `HTTPRouteParentRefPort` | Attach a route to Gateway listeners by `parentRefs[].port`. |
| `HTTPRouteDestinationPortMatching` | A route whose `parentRefs[].port` matches no listener is not accepted: it reports `Accepted=False` with reason `NoMatchingParent`. |

### Rewrites, redirects, and response headers

| Feature | What it adds |
|---|---|
| `HTTPRouteHostRewrite` | `URLRewrite` replaces the `Host` header sent to the backend. |
| `HTTPRoutePathRewrite` | `URLRewrite` replaces the full path or a path prefix. |
| `HTTPRoutePathRedirect` | `RequestRedirect` sets the redirect path. |
| `HTTPRoutePortRedirect` | `RequestRedirect` sets the redirect port. |
| `HTTPRouteSchemeRedirect` | `RequestRedirect` sets the redirect scheme. |
| `HTTPRoute303RedirectStatusCode` | Redirect with status 303. |
| `HTTPRoute307RedirectStatusCode` | Redirect with status 307. |
| `HTTPRoute308RedirectStatusCode` | Redirect with status 308. |
| `HTTPRouteResponseHeaderModification` | `ResponseHeaderModifier` sets, adds, or removes response headers. |

A rule cannot combine `RequestRedirect` and `URLRewrite`; Flareway drops that rule.

### Mirroring

| Feature | What it adds |
|---|---|
| `HTTPRouteRequestMirror` | Copy requests to a second backend. |
| `HTTPRouteRequestMultipleMirrors` | Copy requests to more than one backend. |
| `HTTPRouteRequestPercentageMirror` | Copy only a percentage of requests. |

### Timeouts

| Feature | What it adds |
|---|---|
| `HTTPRouteRequestTimeout` | `timeouts.request` bounds the whole request. |
| `HTTPRouteBackendTimeout` | `timeouts.backendRequest` bounds each request to a backend. |

### CORS

| Feature | What it adds |
|---|---|
| `HTTPRouteCORS` | The `CORS` filter applies a cross-origin resource sharing policy to the route. |

### Backend protocols

| Feature | What it adds |
|---|---|
| `HTTPRouteBackendProtocolH2C` | Cleartext HTTP/2 to a Service port with `appProtocol: kubernetes.io/h2c`. |
| `HTTPRouteBackendProtocolWebSocket` | WebSocket to a Service port with an `appProtocol` of `kubernetes.io/ws` or `kubernetes.io/wss`. |

### Backend TLS

| Feature | What it adds |
|---|---|
| `BackendTLSPolicy` | Envoy connects to the backend over TLS and verifies its certificate. |
| `BackendTLSPolicySANValidation` | Verify the backend certificate against listed subject alternative names. |

### Listeners and infrastructure

| Feature | What it adds |
|---|---|
| `GatewayHTTPListenerIsolation` | A request reaches only the routes of the listener with the most specific matching hostname. |
| `GatewayHTTPSListenerDetectMisdirectedRequests` | Envoy answers 421 when an HTTPS request's `Host` does not match the listener chosen by the TLS server name. |
| `GatewayInfrastructurePropagation` | Labels and annotations in `spec.infrastructure` are copied to the data-plane Deployment and pods. |

The two listener features were verified in conformance mode, where clients connect to Envoy directly. They do not apply on the Cloudflare edge path.

## Not supported, and what happens

Flareway does not claim these Extended features. Where it rejects or drops the configuration, the status says so:

| Feature | What happens |
|---|---|
| `HTTPRouteRetry`, `HTTPRouteRetryBackendTimeout`, `HTTPRouteRetryConnectionError` | A rule with `retry` is dropped. The route reports `PartiallyInvalid=True` with a `Dropped Rule` message, or `Accepted=False` when every rule is dropped. |
| `GatewayStaticAddresses`, `GatewayAddressEmpty` | A Gateway with any `spec.addresses` entry, including one without a value that asks for a dynamically assigned address, reports `Accepted=False` with reason `UnsupportedAddress`. Cloudflare's edge owns the public addresses. A Gateway with a public listener reports the tunnel's `<tunnel-id>.cfargotunnel.com` hostname as its address. |
| `ListenerSet` | A Gateway with `spec.allowedListeners` reports `Accepted=False` with reason `ListenersNotValid`. |
| `GatewayPort8080` | Public listeners must be HTTP on port 80 or HTTPS on port 443. Any other port marks the listener `PortUnavailable`. Private HTTPS listeners accept any port. |
| `GatewayBackendClientCertificate`, `GatewayFrontendClientCertificateValidation`, `GatewayFrontendClientCertificateValidationInsecureFallback`, `HTTPRouteBackendRequestHeaderModification`, `HTTPRouteNamedRouteRule` | Flareway does not claim these features. Do not depend on them. |

Some configuration falls outside the feature list:

- `sessionPersistence` is dropped the same way as `retry`.
- A listener whose `allowedRoutes.kinds` names anything other than `HTTPRoute`, such as `GRPCRoute`, `TLSRoute`, `TCPRoute`, or `UDPRoute`, reports `ResolvedRefs=False` with reason `InvalidRouteKinds`.
- An `ExtensionRef` filter sets the route's `ResolvedRefs=False` with reason `InvalidKind`, and Envoy answers matching requests with HTTP 500, as the Gateway API specification requires.
- For TCP, SSH, RDP, or other non-HTTP private services, use a `NetworkRoute` over WARP (see [Private services over WARP](../get-started/private-services-over-warp.md)) or a Direct-mode tunnel (see [Direct tunnels](../get-started/direct-tunnels.md)).

## Edge constraints that still apply

Public traffic passes through Cloudflare's edge before it reaches `cloudflared`, so Cloudflare's own limits apply on top of your `HTTPRoute`. Cloudflare waits 100 seconds for response headers (up to 6,000 seconds on Enterprise plans), caps request bodies by plan (100 MB on Free and Pro), and closes WebSocket connections after 100 seconds idle. Server-sent events need responses that the edge does not buffer.

`HTTPRoutePortRedirect` and `HTTPRouteSchemeRedirect` work in Envoy, but Cloudflare's edge serves Flareway hostnames only on ports 80 and 443. A redirect to another port on a public hostname leads to a destination the edge does not serve. Flareway accepts the route anyway.

See [Limits](limits.md) for the rest of Flareway's boundaries.

## Evidence

The supported feature names on this page are the list the controller publishes in `GatewayClass.status.supportedFeatures` (`internal/gatewayapi/features.go`). A local Gateway API conformance run tested every one of them; the [conformance report](../conformance/v1.6.2/flareway/README.md) gives the results and what the run did not cover.
