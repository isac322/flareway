# Connect a Cloudflare account

Create a scoped Cloudflare API token, store it in a Secret, declare a `CloudflareAccount` whose grants limit what namespaces can publish, and create the `GatewayClass` that uses the account.

## Create a scoped API token

Create a scoped API token for the account; do not use the Global API Key. Grant only the capabilities that the enabled controllers and your resources need:

| Feature | Required Cloudflare capability |
|---|---|
| Account verification | Read account, zones, token verification, and Zero Trust organization metadata |
| Managed tunnels | Read/write Cloudflare Tunnels, tunnel tokens, and tunnel configurations |
| Managed public DNS | Read zones and read/write DNS records for the granted zones |
| Access | Read/write Access applications, reusable policies, groups, identity providers, posture rules, and service tokens used by the installation |
| Private network | Read/write virtual networks, CIDR routes, and private hostname routes |
| Device settings | Read/write device profiles, split-tunnel lists, fallback domains, and device settings |
| Organization | Read/write Zero Trust organization settings, Gateway rules, and Gateway lists |

Cloudflare's dashboard permission labels may group these API families differently. Start with a token limited to the target account and zones, and add a permission only when Cloudflare reports an authorization failure for a call (see [Verify the account](#verify-the-account)). [Security model](../concepts/security-model.md) explains how the token and the account grants divide authority.

## Store the token in a Secret

The Secret lives in the namespace that the account's `apiTokenSecretRef` names. The normal location is `flareway-system`:

```sh
kubectl -n flareway-system create secret generic cloudflare-api-token \
  --from-literal=api-token='<scoped-token>'
```

The controller never writes API tokens to status, Events, or request logs.

## Declare the account and its grants

`CloudflareAccount` is cluster-scoped. This manifest is `config/samples/flareway_v1alpha1_cloudflareaccount.yaml`. It also creates the `flareway-platform` namespace, which holds the shared objects that tenant namespaces reference, such as Access policies, custom pages, private networking, and the Direct tunnel. Replace `accountId` with your 32-character Cloudflare account ID and the example hostnames and zones with your own:

```yaml
# flareway-platform holds shared objects that tenants use but do not own:
# Access policies, groups, identity providers, custom pages, device posture,
# service tokens, standalone applications, private networking, WARP
# connectors, the Direct tunnel, and the private Gateway.
apiVersion: v1
kind: Namespace
metadata:
  name: flareway-platform
  labels:
    # The private-https AccessApplication in this namespace sets originJWT Disabled.
    flareway.bhyoo.com/allow-origin-jwt-disable: "true"
---
apiVersion: flareway.bhyoo.com/v1alpha1
kind: CloudflareAccount
metadata:
  name: example-account
spec:
  accountId: "00000000000000000000000000000000"
  credentials:
    apiTokenSecretRef:
      name: cloudflare-api-token
      namespace: flareway-system
      key: api-token
  grants:
  # Tenant grant: public hostnames and references to shared objects in
  # flareway-platform. Tenants cannot create platform objects.
  - namespaceSelector:
      matchLabels:
        kubernetes.io/metadata.name: default
    hostnames:
    - "*.example.com"
    zones:
    - example.com
    exposures:
    - Public
    unprotectedHostnames:
    - app.example.com
    - public.example.com
    accessPolicyRefs: Allowed
    accessCustomPageRefs: Allowed
    backends:
      namespaces: Same
      kinds:
      - Service
    platformObjects: Denied
  # Platform grant: shared objects, the Direct tunnel's public hostnames, and
  # private hostnames and routes served through the private Gateway and WARP
  # connectors.
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

A namespace that matches no grant is denied. The first grant is the tenant grant. It lets the `default` namespace do the following, and nothing more:

- `hostnames`: publish hostnames that match `*.example.com`. A wildcard matches exactly one DNS label and never the zone apex.
- `zones`: write DNS records in `example.com`.
- `exposures`: use public listeners only. WARP private listeners need `Private`.
- `unprotectedHostnames`: serve `app.example.com` and `public.example.com` without Cloudflare Access. This list is a security boundary. Add a hostname only when the platform intends to serve at least one route on it without Access; every other granted hostname requires an Access application.
- `accessPolicyRefs`: reference platform Access policy objects, such as the shared policies in `flareway-platform`.
- `accessCustomPageRefs`: reference `AccessCustomPage` objects, such as the shared custom page in `flareway-platform`.
- `backends`: send traffic only to Services in the route's own namespace.
- `platformObjects`: create or manage no platform-scoped objects. Tenant namespaces keep `Denied`.

The second grant is the platform grant for `flareway-platform`. It sets `platformObjects: Allowed`, so that namespace can manage the shared objects. It also allows public and private listeners, the Direct tunnel's `*.direct.example.com` hostnames without Access, and private hostnames under `*.internal.example`, and its `privateRoutes` selectors let the namespace reference the `NetworkRoute` and `HostnameRoute` objects labeled `flareway.bhyoo.com/private-route: platform`.

The tenant grant covers the next guide, which publishes a public route. [Security model](../concepts/security-model.md) describes every grant field.

Save the manifest as `cloudflareaccount.yaml` and apply it:

```sh
kubectl apply -f cloudflareaccount.yaml
```

## Verify the account

```sh
kubectl get cloudflareaccount example-account
kubectl describe cloudflareaccount example-account
```

The account is ready when both the `ACCEPTED` and `CREDENTIALS` columns show `True`; `ACCOUNT` shows the account name that Cloudflare returned. The two conditions fail separately, so check both:

- `CredentialsValid=False` means the token cannot be used at all. The reason is `SecretNotFound`, `SecretKeyNotFound`, or `CredentialsInvalid` (Cloudflare rejected the token or reports it inactive). Fix the Secret reference or the token.
- `CredentialsValid=True` with `Accepted=False` means the token is active but a verification read failed. Reason `CloudflareAPIError` with the message "Cloudflare zones could not be listed" or "Cloudflare Zero Trust organization could not be read" names the call. Check the controller log for that call's error: add the read permission only if Cloudflare reports an authorization failure; for connectivity, rate-limit, or server errors, keep the token scope and let the controller retry. Reason `InvalidOrganization` means the Zero Trust organization returned an unusable auth domain.

Once the account is accepted, `status.verified.zones` lists the zones the token can see. Check that the zones in your grant appear there. [Troubleshooting](../operations/troubleshooting.md) covers the other conditions.

## Create the GatewayClass

Gateways use the class `flareway`, and its `GatewayClassConfig/default` names the class's default `CloudflareAccount`. The API server rejects a `GatewayClassConfig` that names no account unless it runs in conformance mode, which is why the install step left the class out. Upgrade the release, keep its other values, and point the class at the account:

```sh
helm upgrade flareway oci://ghcr.io/isac322/charts/flareway \
  --version <chart-version> \
  --namespace flareway-system \
  --reuse-values \
  --set gatewayClass.create=true \
  --set gatewayClass.config.accountRefName=example-account
```

Use the same `<chart-version>` as the install. If you named the account differently, pass that name instead of `example-account`.

Check the class:

```sh
kubectl get gatewayclass flareway
```

The class is ready when `ACCEPTED` shows `True`. Flareway sets the `Accepted` condition with reason `Accepted` once `GatewayClassConfig/default` exists. If the condition is `False` with reason `InvalidParameters`, `kubectl describe gatewayclass flareway` shows why, for example that the `GatewayClassConfig` was not found.

Next: [Expose a Service through Cloudflare Tunnel](expose-a-service.md).
