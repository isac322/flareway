# Reach private Services over Cloudflare WARP

Serve a Service only to WARP devices through a private Gateway listener, with Envoy terminating TLS and virtual networks and routes as CRDs.

The private path uses the same `Gateway`, `HTTPRoute`, and `AccessApplication` objects as a public one. Live acceptance of the private-hostname answer by the Cloudflare edge has not been verified; see [Limits](../concepts/limits.md#private-listeners) and [What is not verified live](#what-is-not-verified-live).

This page serves `admin.internal.example` from the `flareway-platform` namespace, where the shared Access objects from [Protect a route with Cloudflare Access](protect-with-access.md) already live. A private listener needs a `VirtualNetwork` in its own namespace, and only a namespace whose grant sets `platformObjects: Allowed` can manage one, so the private Gateway, its routes, and its Access applications all live there. The manifests are the samples in [`config/samples/`](../../config/samples/). Replace every ID, name, and hostname with your own.

## Before you start

Your Cloudflare account needs:

- `gatewayProxyEnabled` and `gatewayUdpProxyEnabled` turned on in the account's device settings. Flareway reads them from Cloudflare before it programs a private listener.
- a device profile in Include mode that includes the private hostname ranges, if you use Include mode;
- no overlap between a hostname route and a fallback DNS suffix;
- a compatible WARP client and Cloudflare plan.

The API token needs the Private network capability (read and write virtual networks, CIDR routes, and private hostname routes) and read access to device settings. [Connect a Cloudflare account](connect-cloudflare.md) lists every capability.

This page also uses the `flareway-platform` grant from [Connect a Cloudflare account](connect-cloudflare.md) and the Access policies from [Protect a route with Cloudflare Access](protect-with-access.md).

## Create the Service and certificate

[`flareway_v1alpha1_cloudflareaccount.yaml`](../../config/samples/flareway_v1alpha1_cloudflareaccount.yaml) creates `flareway-platform` with the label `flareway.bhyoo.com/allow-origin-jwt-disable: "true"`, which approves the `originJWT.mode: Disabled` application in [Protect it with Access](#protect-it-with-access).

In `flareway-platform`, you also need:

- a Service named `demo-admin` that serves HTTP on port `9090`, or change the `HTTPRoute` backend below to a Service you already run;
- a TLS Secret named `admin-internal-tls` for `admin.internal.example`. Envoy serves this certificate to WARP devices, so they must trust it. Flareway does not issue certificates; use cert-manager or an internal CA.

## Check the grant

The `flareway-platform` grant from [Connect a Cloudflare account](connect-cloudflare.md) already covers this page:

```yaml
  - namespaceSelector:
      matchLabels:
        kubernetes.io/metadata.name: flareway-platform
    hostnames:
    - "*.direct.example.com"
    - "*.internal.example"
    zones:
    - example.com
    exposures:
    - Public
    - Private
    unprotectedHostnames:
    - "*.direct.example.com"
    privateRoutes:
      networkRouteSelector:
        matchLabels:
          flareway.bhyoo.com/private-route: platform
      hostnameRouteSelector:
        matchLabels:
          flareway.bhyoo.com/private-route: platform
    backends:
      namespaces: Same
      kinds:
      - Service
    platformObjects: Allowed
```

Each field opens one gate for this page:

- `*.internal.example` in `hostnames` and `Private` in `exposures` allow the private listener. A grant needs at least one zone; Flareway does not check private hostnames against `zones`.
- `privateRoutes` selects the `HostnameRoute` and `NetworkRoute` objects the namespace may use, by their `flareway.bhyoo.com/private-route: platform` label.
- `backends` lets the `HTTPRoute` send traffic to Services in `flareway-platform`.
- `platformObjects: Allowed` lets `flareway-platform` hold `VirtualNetwork`, `HostnameRoute`, `NetworkRoute`, and `WARPConnector` objects.

The applications on this page reference policies in their own namespace, so they need no `accessPolicyRefs`. `admin.internal.example` is not in `unprotectedHostnames`, so the hostname stays blocked until an `AccessApplication` protects it. The [security model](../concepts/security-model.md) explains why grants and Kubernetes RBAC must both allow each object.

## Declare the virtual network and routes

A `VirtualNetwork` owns one account-scoped Cloudflare virtual network. A private listener uses a virtual network from its own namespace: the one its tunnel listener names in `virtualNetworkRef`, or, without a reference, the one with `isDefault: true`. This is [`flareway_v1alpha1_virtualnetwork.yaml`](../../config/samples/flareway_v1alpha1_virtualnetwork.yaml):

```yaml
apiVersion: flareway.bhyoo.com/v1alpha1
kind: VirtualNetwork
metadata:
  name: private-services
  namespace: flareway-platform
spec:
  accountRef:
    name: example-account
  name: private-services
  isDefault: false
  comment: Example private services
  managementPolicy: Managed
  deletionPolicy: Orphan
```

A `HostnameRoute` sends one private hostname to the tunnel. This is `private-admin` from [`flareway_v1alpha1_hostnameroute.yaml`](../../config/samples/flareway_v1alpha1_hostnameroute.yaml):

```yaml
apiVersion: flareway.bhyoo.com/v1alpha1
kind: HostnameRoute
metadata:
  name: private-admin
  namespace: flareway-platform
  labels:
    flareway.bhyoo.com/private-route: platform
spec:
  accountRef:
    name: example-account
  hostname: admin.internal.example
  tunnelRef:
    kind: CloudflareTunnel
    name: private-gateway
    namespace: flareway-platform
  allowedNamespaces:
    from: Same
  comment: Private admin hostname through the Gateway tunnel
  managementPolicy: Managed
  deletionPolicy: Delete
```

A `NetworkRoute` sends a CIDR to the tunnel, here the Kubernetes Service range. This is `private-services` from [`flareway_v1alpha1_networkroute.yaml`](../../config/samples/flareway_v1alpha1_networkroute.yaml); its `virtualNetworkRef` names the `VirtualNetwork` above, which must be in the route's own namespace:

```yaml
apiVersion: flareway.bhyoo.com/v1alpha1
kind: NetworkRoute
metadata:
  name: private-services
  namespace: flareway-platform
  labels:
    flareway.bhyoo.com/private-route: platform
spec:
  accountRef:
    name: example-account
  network: 10.96.0.0/12
  tunnelRef:
    kind: CloudflareTunnel
    name: private-gateway
    namespace: flareway-platform
  virtualNetworkRef:
    name: private-services
  allowedNamespaces:
    from: Same
  comment: Kubernetes Service CIDR through the Gateway tunnel
  managementPolicy: Managed
  deletionPolicy: Delete
```

`tunnelRef.kind` is `CloudflareTunnel` or `WARPConnector` and defaults to `CloudflareTunnel`. Without `virtualNetworkRef`, a route uses the account's default virtual network. `allowedNamespaces` decides which namespaces the route admits: the referenced tunnel's namespace must be admitted, and so must the namespace of any `DeviceProfile` that includes the route. With `from: Same`, the tunnel must be in the route's namespace. An `AccessApplication` references a route in its own namespace. The routes wait with `Pending` until the tunnel below exists and is accepted.

A private listener can also get its `HostnameRoute` automatically: by default, Flareway creates one in its own namespace for each private listener hostname. This page declares `private-admin` itself and turns that off with `hostnameRoute.create: false`.

## Add the private listener

This is [`gateway_v1_private_gateway.yaml`](../../config/samples/gateway_v1_private_gateway.yaml). The tunnel listener's `virtualNetworkRef` points the listener at `private-services`.

```yaml
apiVersion: flareway.bhyoo.com/v1alpha1
kind: CloudflareTunnel
metadata:
  name: private-gateway
  namespace: flareway-platform
spec:
  accountRef:
    name: example-account
  tunnel:
    name: flareway-example-private-gateway
  configuration:
    # Gateway owns the complete remote ingress program for this tunnel.
    mode: Gateway
  managementPolicy: Managed
  deletionPolicy: Delete
  dns:
    mode: External
  listeners:
  - name: admin-private
    exposure: Private
    virtualNetworkRef:
      name: private-services
    hostnameRoute:
      create: false
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: private-gateway
  namespace: flareway-platform
spec:
  gatewayClassName: flareway
  infrastructure:
    parametersRef:
      group: flareway.bhyoo.com
      kind: CloudflareTunnel
      name: private-gateway
  listeners:
  - name: admin-private
    hostname: admin.internal.example
    port: 443
    protocol: HTTPS
    tls:
      mode: Terminate
      certificateRefs:
      - kind: Secret
        name: admin-internal-tls
    allowedRoutes:
      namespaces:
        from: Same
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: private-admin
  namespace: flareway-platform
spec:
  parentRefs:
  - name: private-gateway
    sectionName: admin-private
  hostnames:
  - admin.internal.example
  rules:
  - backendRefs:
    - name: demo-admin
      port: 9090
```

A private listener needs three things:

- `protocol: HTTPS` with a `certificateRefs` Secret. Envoy terminates TLS for private listeners, the reverse of public listeners, where Cloudflare owns edge TLS.
- a `CloudflareTunnel.spec.listeners[]` entry with the same name and `exposure: Private`.
- the port that clients dial. Envoy binds to the listener's declared port, here `443`, because Cloudflare forwards the original destination port. Another port would break the WARP destination and the Access `portRange`.

One Gateway cannot expose the same hostname as both public and private; the tunnel reports `Accepted=False` with "hostname exposure must be unique per Gateway". `dns.mode: External` fits a private-only tunnel, which needs no public DNS record.

## Protect it with Access

The hostname forwards no traffic until an `AccessApplication` protects it. Private hostnames take the same `AccessApplication` as public ones, with one difference: `cloudflared` does not check them, so Envoy's `jwt_authn` filter is the only origin JWT check. Cloudflare can add the Access JWT to private traffic only when Zero Trust Gateway TLS decryption is on. Flareway does not observe that setting, so an application with `originJWT.mode: Required` on a private listener stays blocked and unprogrammed until you set `originJWT.assumeGatewayTLSDecryption: true`. That field records the platform's promise that decryption is on.

This is `private-https` from [`flareway_v1alpha1_accessapplication_private.yaml`](../../config/samples/flareway_v1alpha1_accessapplication_private.yaml). A `targetRefs` application must share its Gateway's namespace, and it uses the policies from the Protect guide in the same namespace:

```yaml
apiVersion: flareway.bhyoo.com/v1alpha1
kind: AccessApplication
metadata:
  name: private-https
  namespace: flareway-platform
spec:
  accountRef:
    name: example-account
  type: SelfHosted
  selfHosted: {}
  targetRefs:
  - group: gateway.networking.k8s.io
    kind: Gateway
    name: private-gateway
    sectionName: admin-private
  application:
    name: Private HTTPS
    sessionDuration: 720h
    allowAuthenticateViaWarp: true
    appLauncherVisible: false
  policies:
  - policyRef:
      name: allow-developers-warp
  - policyRef:
      name: deny-everyone
  originJWT:
    mode: Disabled
  managementPolicy: Managed
  deletionPolicy: Delete
```

`private-https` protects the private listener with Access at the edge only, because `originJWT.mode` is `Disabled`; the `flareway-platform` namespace label allows that. For an origin JWT check on this listener, turn on Zero Trust Gateway TLS decryption and set `originJWT.mode: Required` with `assumeGatewayTLSDecryption: true`. [Security model](../concepts/security-model.md#access-enforcement) compares the public and private checks.

## How resolution works

A Gateway with private listeners gets a CoreDNS sidecar in its data-plane Pod. The sidecar answers private hostnames with `127.0.0.1`, so WARP traffic that arrives through `cloudflared` goes to Envoy on loopback. Envoy terminates TLS with your certificate and applies the `HTTPRoute` rules.

The tunnel's `PrivateListenerDegraded` condition reports how the listener is bound:

| Status and reason | Meaning |
|---|---|
| `False`, `Loopback` | Private listeners are isolated on Pod loopback. |
| `False`, `Pending` | A private prerequisite is missing; the message names it, such as a missing virtual network or `HostnameRoute`. |
| `True`, `PodIPFallback` | The listener uses the Pod IP instead of loopback and relies on NetworkPolicy isolation. Verify the NetworkPolicy before you treat the listener as ready. |

## Verify

Check the Gateway, the tunnel, the application, and the private-network objects:

```sh
kubectl -n flareway-platform get gateway private-gateway
kubectl -n flareway-platform get cloudflaretunnel private-gateway \
  -o jsonpath='{range .status.conditions[*]}{.type}={.status} {.reason}{"\n"}{end}'
kubectl -n flareway-platform get accessapplication private-https
kubectl -n flareway-platform get virtualnetwork,hostnameroute,networkroute
```

When the Gateway reports `Programmed=True`, request the hostname from an enrolled WARP device. Cloudflare Access evaluates the request against the policies, and an allowed request reaches `demo-admin`:

```sh
curl https://admin.internal.example/
```

## Protect a private CIDR

An `AccessApplication` can also protect a CIDR behind a `NetworkRoute`, without a Gateway target. This is `private-l4` from [`flareway_v1alpha1_accessapplication_private.yaml`](../../config/samples/flareway_v1alpha1_accessapplication_private.yaml). It lives in `flareway-platform` next to its route, and its `cidr` lies inside the route's `10.96.0.0/12`:

```yaml
apiVersion: flareway.bhyoo.com/v1alpha1
kind: AccessApplication
metadata:
  name: private-l4
  namespace: flareway-platform
spec:
  accountRef:
    name: example-account
  type: SelfHosted
  selfHosted: {}
  destinations:
  - type: Private
    private:
      networkRouteRef:
        name: private-services
      # cidr must lie inside the NetworkRoute network (10.96.0.0/12).
      cidr: 10.96.0.0/16
      portRange: "443"
      l4Protocol: TCP
  application:
    name: Private L4 service
    sessionDuration: 720h
    allowAuthenticateViaWarp: true
    appLauncherVisible: false
  policies:
  - policyRef:
      name: allow-developers-warp
  - policyRef:
      name: deny-everyone
  originJWT:
    mode: Required
    assumeGatewayTLSDecryption: true
  managementPolicy: Managed
  deletionPolicy: Delete
```

`networkRouteRef` names a route in the application's namespace. `cidr` must lie inside the route's network, or the application reports `RefNotPermitted`; without `cidr`, the application covers the whole route. Cloudflare Access checks this traffic at the edge only: the traffic does not pass through Envoy's `jwt_authn` filter, so the `originJWT` block has no effect and the application's `OriginJWTEnforced` condition reports `NotApplicable`.

## Connect another site with `WARPConnector`

A `WARPConnector` links another network, such as a branch office or a VPC, to your Cloudflare account. It is a separate Cloudflare Mesh connector with no Gateway data plane. Flareway creates it and stores its bootstrap token in a Secret it owns, which `status.tokenSecretRef` names; you run the connector at that site with the token. From [`flareway_v1alpha1_warpconnector.yaml`](../../config/samples/flareway_v1alpha1_warpconnector.yaml):

```yaml
apiVersion: flareway.bhyoo.com/v1alpha1
kind: WARPConnector
metadata:
  name: branch-local
  namespace: flareway-platform
spec:
  accountRef:
    name: example-account
  name: flareway-example-branch-local
  highAvailability:
    enabled: true
    mode: Local
    local:
      vips:
      - address: 192.0.2.10
      - address: 2001:db8::10
      vipsPrevious:
      - address: 192.0.2.9
  # Change requestId for each deliberate failover, including repeat failover to this client.
  failover:
    clientId: replace-with-linked-client-id
    requestId: replace-with-failover-request-id
  managementPolicy: Managed
  adoption:
    mode: None
  deletionPolicy: Orphan
```

Routes reach the site with `tunnelRef.kind: WARPConnector`. This is `branch-office` from [`flareway_v1alpha1_networkroute.yaml`](../../config/samples/flareway_v1alpha1_networkroute.yaml); it sends the branch CIDR to `branch-local`:

```yaml
apiVersion: flareway.bhyoo.com/v1alpha1
kind: NetworkRoute
metadata:
  name: branch-office
  namespace: flareway-platform
  labels:
    flareway.bhyoo.com/private-route: platform
spec:
  accountRef:
    name: example-account
  network: 10.40.0.0/16
  tunnelRef:
    kind: WARPConnector
    name: branch-local
    namespace: flareway-platform
  # virtualNetworkRef is optional; omission selects the account default virtual network.
  allowedNamespaces:
    from: Same
  comment: Branch CIDR through the local-HA WARP Connector
  managementPolicy: Managed
  deletionPolicy: Delete
```

`highAvailability.enabled` is set at creation and cannot change afterwards. `mode` is `None`, `Disabled`, `AWS`, or `Local`: `AWS` requires `aws.fnrId`, and `Local` requires at least one address in `local.vips`. A failover request needs a linked `clientId` and a new `requestId` each time.

## What is not verified live

Tests measure the CoreDNS sidecar answering `127.0.0.1` locally. No run against a live Cloudflare account has verified that the Cloudflare edge and WARP accept that answer for a private hostname. The design's fallback, in which the sidecar answers with the Pod IP and NetworkPolicy isolates Envoy, is reported as `PrivateListenerDegraded=True`. [Limits](../concepts/limits.md#private-listeners) lists this with the other boundaries.

Next: [Direct tunnels for TCP, SSH, and RDP origins](direct-tunnels.md).
