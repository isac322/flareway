# Expose a Service through Cloudflare Tunnel

Publish a Service on a public hostname with a `CloudflareTunnel`, `Gateway`, and `HTTPRoute`. Flareway creates the tunnel, DNS record, and Envoy routes.

## Before you start

This guide changes a real Cloudflare account. You need:

- Flareway installed as in [Install](install.md).
- The `CloudflareAccount` and `GatewayClass/flareway` from [Connect a Cloudflare account](connect-cloudflare.md). The account shows `Accepted` and `CredentialsValid` both `True`, its token has the tunnel and DNS capabilities, and the class shows `Accepted=True`.
- A namespace that matches the account's grant. The examples use `default`.
- A hostname in a zone the grant allows. Because this route has no Access application, the hostname must also be listed in the grant's `unprotectedHostnames`.
- A Service to publish in the same namespace. The examples send traffic to `example-service` on port 8080.

The manifests below come from [`config/samples/`](../../config/samples/). Replace `example.com`, `example-account`, and `example-service` with your own names.

## Create the CloudflareTunnel

A `CloudflareTunnel` declares the remote tunnel, its DNS policy, and the listeners it serves. This is `config/samples/flareway_v1alpha1_cloudflaretunnel.yaml`:

```yaml
apiVersion: flareway.bhyoo.com/v1alpha1
kind: CloudflareTunnel
metadata:
  name: public
  namespace: default
spec:
  accountRef:
    name: example-account
  tunnel:
    name: flareway-example-public
  configuration:
    # Gateway mode is the sole writer of ingress assembled from Gateway API resources.
    mode: Gateway
  managementPolicy: Managed
  adoption:
    mode: None
  deletionPolicy: Delete
  dns:
    mode: Managed
    recordComment: example public tunnel
    proxied: true
    ttl: 1
  listeners:
  - name: web
    exposure: Public
```

- `accountRef` names the account whose grant must allow this namespace.
- `tunnel.name` is the tunnel name in Cloudflare.
- `configuration.mode: Gateway` makes the Gateway the only writer of the tunnel's ingress configuration.
- `managementPolicy: Managed` with `adoption.mode: None` creates a new tunnel instead of taking over an existing one. `deletionPolicy: Delete` removes the remote tunnel when you delete this object. [Ownership and adoption](../concepts/ownership-and-adoption.md) covers the other policies.
- `dns.mode: Managed` lets Flareway write the DNS record. `proxied: true` requires `ttl: 1`, which means automatic.
- `listeners` marks the Gateway listener `web` as public.

## Create the Gateway

This is `config/samples/gateway_v1_gateway.yaml`, unchanged:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: public
  namespace: default
spec:
  gatewayClassName: flareway
  infrastructure:
    parametersRef:
      group: flareway.bhyoo.com
      kind: CloudflareTunnel
      name: public
  listeners:
  - name: web
    hostname: app.example.com
    port: 80
    protocol: HTTP
    allowedRoutes:
      namespaces:
        from: Same
```

`infrastructure.parametersRef` binds the Gateway to the `CloudflareTunnel` named `public` in the same namespace. That reference is the whole link; the Gateway carries no Flareway annotations. Cloudflare owns edge TLS for public listeners, so the listener has no `certificateRefs`.

## Create the HTTPRoute

This is `config/samples/gateway_v1_httproute.yaml`, unchanged:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: public
  namespace: default
spec:
  parentRefs:
  - name: public
    sectionName: web
  hostnames:
  - app.example.com
  rules:
  - matches:
    - path:
        type: PathPrefix
        value: /
    backendRefs:
    - name: example-service
      port: 8080
```

The route attaches to the `web` listener and sends every path on `app.example.com` to `example-service`. Apply the three manifests with `kubectl apply -f`.

## What Flareway creates

- The Cloudflare Tunnel `flareway-example-public`.
- A data-plane Deployment, `flareway-gw-public` in `default`, whose pod runs `cloudflared` and Envoy. `cloudflared` opens outbound connections to Cloudflare's edge, so the cluster needs no inbound ports or public IPs.
- A proxied CNAME record for `app.example.com` that points to the tunnel, with Flareway's ownership marked in the record comment.
- Envoy routes for the `HTTPRoute`, streamed from the controller over xDS. `cloudflared` forwards requests to Envoy over loopback, and Envoy applies the route rules.

## Verify

```sh
kubectl get gateway -n default public
kubectl get cloudflaretunnel -n default public
```

Wait for the Gateway's `PROGRAMMED` column to show `True`. Flareway reports `Programmed=True` only after edge DNS, tunnel sessions, the xDS configuration, and the Envoy data plane have all converged. The `CloudflareTunnel` shows the remote tunnel ID and `READY` as `True`.

If `Programmed` stays `False`, run `kubectl describe gateway -n default public` and read the condition's reason and message. Reason `Pending` names the gate that has not converged yet. `DNSReady=False` on the tunnel means the zone is not granted or discovered, or an existing record carries a foreign ownership comment. [Troubleshooting](../operations/troubleshooting.md) lists every condition.

Once the Gateway is programmed, request the hostname:

```sh
curl https://app.example.com/
```

The response comes from `example-service`.

## Go further

Header, method, and query matches, rewrites, mirrors, and weighted backends are standard `HTTPRoute` fields. [HTTP routing](../concepts/http-routing.md) lists what Flareway supports.

Next: [Protect a route with Cloudflare Access](protect-with-access.md).
