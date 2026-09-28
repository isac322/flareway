# Protect a route with Cloudflare Access

Attach an `AccessApplication` to a Gateway listener or `HTTPRoute` rule. Flareway creates the Access app and verifies the Access JWT at the origin.

This page continues from [Expose a Service through Cloudflare Tunnel](expose-a-service.md) and protects the `public` Gateway in the `default` namespace. The manifests come from [`config/samples/`](../../config/samples/). Replace every ID, name, and hostname in them with your own.

## Before you start

The API token of the `CloudflareAccount` needs the Access capability: read and write Access applications, reusable policies, groups, identity providers, posture rules, and service tokens. [Connect a Cloudflare account](connect-cloudflare.md) lists every capability.

Flareway reads your Zero Trust team name and team domain when it verifies the account. A protected hostname forwards no traffic until Flareway has both and the application's AUD tag.

The grant that selects your namespace decides what an `AccessApplication` may do:

- `hostnames` and `zones` must cover the protected hostname.
- `unprotectedHostnames` is a security boundary. List a hostname there only when at least one of its routes should be served without Access. Public paths carved out below a protected path need it.
- `accessPolicyRefs: Allowed` lets an application reference an `AccessPolicy` or `AccessGroup` in another namespace.
- Flareway treats `AccessPolicy`, `AccessGroup`, `IdentityProvider`, `AccessCustomPage`, and `DevicePostureRule` as platform objects, even when it only observes them. The namespace that holds them needs a grant with `platformObjects: Allowed`.

The grant in [Connect a Cloudflare account](connect-cloudflare.md) sets `platformObjects: Denied` for `default`. Before you create the objects on this page, change it to `platformObjects: Allowed` in `cloudflareaccount.yaml` and apply the file again. The later guides reference these policies from other namespaces, so they stay in `default`.

To keep the policies in a namespace your platform team controls instead, reference them with `policyRef.namespace`; the application's grant needs `accessPolicyRefs: Allowed`. Identity provider references have no namespace: `allowedIdpRefs[].name` names an `IdentityProvider` in the application's own namespace, and `allowedIdpRefs[].externalId` names a Cloudflare identity provider by ID without any object. A custom page in another namespace uses `customPageRefs[].objectRef.namespace` and needs `accessCustomPageRefs: Allowed`.

## Reuse existing policies and identity providers

An `AccessApplication` attaches policies through `AccessPolicy` objects and names identity providers through `IdentityProvider` objects. To use a policy or identity provider that already exists in Cloudflare, declare it with `managementPolicy: ObserveOnly` and its Cloudflare ID in `externalRef`. Flareway reads the remote object and reports it in status, and never changes it. With `deletionPolicy: Orphan`, deleting the Kubernetes object leaves the Cloudflare object in place.

From [`flareway_v1alpha1_identityprovider_observeonly.yaml`](../../config/samples/flareway_v1alpha1_identityprovider_observeonly.yaml):

```yaml
apiVersion: flareway.bhyoo.com/v1alpha1
kind: IdentityProvider
metadata:
  name: google
  namespace: default
spec:
  accountRef:
    name: example-account
  type: Google
  name: Google
  managementPolicy: ObserveOnly
  externalRef:
    idpId: "00000000-0000-0000-0000-000000000001"
  deletionPolicy: Orphan
```

From [`flareway_v1alpha1_accesspolicies_observeonly.yaml`](../../config/samples/flareway_v1alpha1_accesspolicies_observeonly.yaml):

```yaml
apiVersion: flareway.bhyoo.com/v1alpha1
kind: AccessPolicy
metadata:
  name: deny-everyone
  namespace: default
spec:
  accountRef:
    name: example-account
  name: deny-everyone
  decision: Deny
  include:
  - everyone: {}
  managementPolicy: ObserveOnly
  externalRef:
    policyId: replace-with-existing-deny-policy-id
  deletionPolicy: Orphan
```

The same file declares `allow-developers-warp`, an observed `Allow` policy that includes the `developers` group and requires the `warp` posture rule. Their samples are [`flareway_v1alpha1_accessgroup_observeonly.yaml`](../../config/samples/flareway_v1alpha1_accessgroup_observeonly.yaml) and [`flareway_v1alpha1_deviceposturerule_observeonly.yaml`](../../config/samples/flareway_v1alpha1_deviceposturerule_observeonly.yaml). It also declares `bypass-public-api`, a managed `Bypass` policy used for public carve-outs below.

An application can also attach a Cloudflare policy directly by ID with `externalRef.policyId` in its `policies` list, without an `AccessPolicy` object.

## Attach an `AccessApplication`

This application protects the `web` listener of the `public` Gateway, so every path on `app.example.com` requires Access. It comes from [`flareway_v1alpha1_accessapplication_variants.yaml`](../../config/samples/flareway_v1alpha1_accessapplication_variants.yaml) and also references the custom page in [`flareway_v1alpha1_accesscustompage.yaml`](../../config/samples/flareway_v1alpha1_accesscustompage.yaml):

```yaml
apiVersion: flareway.bhyoo.com/v1alpha1
kind: AccessApplication
metadata:
  name: demo-admin
  namespace: default
spec:
  accountRef:
    name: example-account
  type: SelfHosted
  selfHosted: {}
  targetRefs:
  - group: gateway.networking.k8s.io
    kind: Gateway
    name: public
    sectionName: web
  application:
    name: Demo application
    sessionDuration: 720h
    allowAuthenticateViaWarp: true
    autoRedirectToIdentity: true
    allowedIdpRefs:
    - name: google
    appLauncherVisible: true
    customPageRefs:
    - objectRef:
        name: accesscustompage-sample
    tags:
    - example
    - admin
  policies:
  - policyRef:
      name: allow-developers-warp
  - policyRef:
      name: deny-everyone
  originJWT:
    mode: Required
    audienceScope: Application
  managementPolicy: Managed
  deletionPolicy: Delete
```

```sh
kubectl apply -f demo-admin.yaml
```

The fields that decide what is protected:

- `targetRefs` names a `Gateway` or `HTTPRoute` in the same namespace. On a `Gateway`, `sectionName` selects a listener, and the listener's whole hostname is protected. On an `HTTPRoute`, `sectionName` selects a named rule (`rules[].name`).
- `pathScope` narrows the target's hostname to an `Exact` or `PathPrefix` path, and `type` defaults to `PathPrefix`. It creates a more specific protected area without changing where the route sends traffic.
- `policies` attach in list order, and that order is the precedence in Cloudflare.
- `originJWT.mode` defaults to `Required`. `audienceScope: Application`, the default, accepts only this application's AUD. `Hostname` accepts the AUD of every ready application on the same hostname and works only with `Required`.
- `originJWT.mode: Disabled` turns off the origin check and needs platform approval: the namespace must carry the label `flareway.bhyoo.com/allow-origin-jwt-disable: "true"`. Without it, the application reports `RefNotPermitted`.

## What Flareway configures

Cloudflare Access checks the request at the edge, and the Access JWT is verified again at the origin: by `cloudflared` and Envoy for public hostnames, by Envoy for private ones. For this page's public hostname, Flareway:

1. creates the Access application in Cloudflare, attaches the policies in order, and stores the application's AUD tag in a Secret, so you never copy it by hand;
2. adds `originRequest.access` with the AUD, your team name, and `required: true` to the `cloudflared` ingress rule for the hostname;
3. configures Envoy's `jwt_authn` filter to check the `Cf-Access-Jwt-Assertion` header or the `CF_Authorization` cookie against `https://<team-domain>/cdn-cgi/access/certs`.

Until the AUD and the team domain are known, the hostname stays blocked and `cloudflared` answers `403`. Routes that no `AccessApplication` targets carry no JWT check. [Security model](../concepts/security-model.md#access-enforcement) explains the full mechanism.

`cloudflared` and Envoy verify the JWT without calling Cloudflare, so a revoked session stays valid at the origin until its token expires. [Limits](../concepts/limits.md#timing) gives the timing.

## Carve out public paths

Some paths below a protected application must stay public, such as an API or a health check. [`flareway_v1alpha1_accessapplication_public_carveout.yaml`](../../config/samples/flareway_v1alpha1_accessapplication_public_carveout.yaml) protects the `dashboard` rule at `/` and leaves `/v1` and `/public` open:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: demo-app
  namespace: default
spec:
  gatewayClassName: flareway
  listeners:
  - name: web
    hostname: public.example.com
    port: 80
    protocol: HTTP
    allowedRoutes:
      namespaces:
        from: Same
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: demo-app
  namespace: default
spec:
  parentRefs:
  - name: demo-app
  hostnames:
  - public.example.com
  rules:
  - name: public-v1
    matches:
    - path:
        type: PathPrefix
        value: /v1
    backendRefs:
    - name: demo-app
      port: 2455
  - name: public-content
    matches:
    - path:
        type: PathPrefix
        value: /public
    backendRefs:
    - name: demo-app
      port: 2455
  - name: dashboard
    matches:
    - path:
        type: PathPrefix
        value: /
    backendRefs:
    - name: demo-app
      port: 2455
---
apiVersion: flareway.bhyoo.com/v1alpha1
kind: AccessApplication
metadata:
  name: demo-dashboard
  namespace: default
spec:
  accountRef:
    name: example-account
  type: SelfHosted
  selfHosted: {}
  targetRefs:
  - group: gateway.networking.k8s.io
    kind: HTTPRoute
    name: demo-app
    sectionName: dashboard
  pathScope:
    type: PathPrefix
    value: /
  application:
    name: Demo dashboard
    sessionDuration: 720h
    appLauncherVisible: false
    customPageRefs:
    - objectRef:
        name: accesscustompage-sample
  policies:
  - policyRef:
      name: allow-developers-warp
  - policyRef:
      name: deny-everyone
  originJWT:
    mode: Required
  bypass:
    children:
    - hostname: public.example.com
      path: /v1
      name: Demo public API
      externalRef:
        applicationId: replace-with-existing-bypass-application-id
      adoption:
        mode: AdoptById
        expect:
          name: Demo public API
      deletionPolicy: Orphan
    - hostname: public.example.com
      path: /public
      name: Demo public content
      policyRef:
        policyRef:
          name: bypass-public-api
      deletionPolicy: Delete
  managementPolicy: Managed
  deletionPolicy: Delete
```

This Gateway has no `parametersRef`, so Flareway provisions a `CloudflareTunnel` named after it with the GatewayClass account.

The `/v1` and `/public` rules sit below the protected `/` on the same hostname, so Flareway creates one child bypass Access application for each public path. The hostname must appear in the grant's `unprotectedHostnames`; the Connect Cloudflare grant lists `public.example.com`.

`bypass.children` does not create carve-outs; the routes do. Each entry, keyed by `hostname` and `path`, sets a child's name, deletion policy, and `Bypass` policy, or adopts a child that already exists in Cloudflare. Adoption needs `externalRef.applicationId`, `adoption.mode: AdoptById`, and the expected name; Flareway never adopts a child by hostname or name alone. A child without a `policyRef` gets a bypass-everyone policy that Flareway manages. `status.bypassApplications[]` records each child and whether it was `Created`, `Recovered`, or `Adopted`.

## Verify

Wait for the application, then read its conditions:

```sh
kubectl -n default wait --for=condition=Programmed accessapplication/demo-admin --timeout=5m
kubectl -n default get accessapplication demo-admin \
  -o jsonpath='{range .status.conditions[*]}{.type}={.status} {.reason}{"\n"}{end}'
kubectl -n default get gateway public
```

A protected application reports `Accepted=True`, `Programmed=True`, and `OriginJWTEnforced=True` with reason `Enforced`, and the Gateway keeps `Programmed=True`. While a listener waits for its Access application, the Gateway reports `Programmed=False` with reason `Pending`, and the message names what is missing, such as a policy that is not accepted yet.

Then request the hostname without signing in:

```sh
curl -sI https://app.example.com/
```

Cloudflare Access answers instead of your Service; a browser sees the Access sign-in page.

Deleting an `AccessApplication` never makes a protected route public by itself. The hostname stays blocked unless no `AccessApplication` targets it and the grant lists it in `unprotectedHostnames`. The Connect Cloudflare grant lists `app.example.com` so that the Expose guide works without Access. Once `demo-admin` is programmed, remove `app.example.com` from `unprotectedHostnames` to keep it blocked if the application is ever deleted.

[Troubleshooting](../operations/troubleshooting.md) maps each blocking condition to its cause.

## Other application types

`AccessApplication` also supports `SSH`, `VNC`, `RDP`, `MCP`, and `ProxyEndpoint`, and the variants sample carries one of each. Applications that do not attach to a Gateway, such as SaaS, Bookmark, or WARP enrollment apps, use `AccessStandaloneApplication`. The [API reference](../api-reference.md) documents every field.

Next: [Reach private Services over Cloudflare WARP](private-services-over-warp.md).
