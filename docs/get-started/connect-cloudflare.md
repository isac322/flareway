# Connect a Cloudflare account

Create a scoped Cloudflare API token, store it in a Secret, and declare a `CloudflareAccount` whose grant limits what namespaces can publish.

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

## Declare the account and one grant

`CloudflareAccount` is cluster-scoped. This manifest is `config/samples/flareway_v1alpha1_cloudflareaccount.yaml`; replace `accountId` with your 32-character Cloudflare account ID and the `example.com` names with your own:

```yaml
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
    backends:
      namespaces: Same
      kinds:
      - Service
    platformObjects: Denied
```

A namespace that matches no grant is denied. This grant lets the `default` namespace do the following, and nothing more:

- `hostnames`: publish hostnames that match `*.example.com`. A wildcard matches exactly one DNS label and never the zone apex.
- `zones`: write DNS records in `example.com`.
- `exposures`: use public listeners only. WARP private listeners need `Private`.
- `unprotectedHostnames`: serve `app.example.com` and `public.example.com` without Cloudflare Access. This list is a security boundary. Add a hostname only when the platform intends to serve at least one route on it without Access; every other granted hostname requires an Access application.
- `accessPolicyRefs`: reference platform Access policy objects.
- `backends`: send traffic only to Services in the route's own namespace.
- `platformObjects`: manage no platform-scoped private-network objects. Leave it `Denied` unless the namespace is trusted to create those objects.

This grant covers the next guide, which publishes a public route. The guides after it need more: WARP private listeners need `Private` in `exposures`, and platform-scoped private-network objects need `privateRoutes` selectors or `platformObjects: Allowed`. [Security model](../concepts/security-model.md) describes every grant field.

Save the manifest as `cloudflareaccount.yaml` and apply it:

```sh
kubectl apply -f cloudflareaccount.yaml
```

## Make it the class default

The install command already pointed `GatewayClassConfig/default` at `example-account`. If you gave the account another name, update the class:

```sh
helm upgrade flareway oci://ghcr.io/isac322/charts/flareway \
  --version <chart-version> \
  --namespace flareway-system \
  --reuse-values \
  --set gatewayClass.config.accountRefName=<account-name>
```

`helm show chart oci://ghcr.io/isac322/charts/flareway` prints the latest `version`; release notes are on GitHub Releases.

## Verify the account

```sh
kubectl get cloudflareaccount example-account
kubectl describe cloudflareaccount example-account
```

The account is ready when both the `ACCEPTED` and `CREDENTIALS` columns show `True`; `ACCOUNT` shows the account name that Cloudflare returned. The two conditions fail separately, so check both:

- `CredentialsValid=False` means the token cannot be used at all. The reason is `SecretNotFound`, `SecretKeyNotFound`, or `CredentialsInvalid` (Cloudflare rejected the token or reports it inactive). Fix the Secret reference or the token.
- `CredentialsValid=True` with `Accepted=False` means the token is active but a verification read failed. Reason `CloudflareAPIError` with the message "Cloudflare zones could not be listed" or "Cloudflare Zero Trust organization could not be read" names the call. Check the controller log for that call's error: add the read permission only if Cloudflare reports an authorization failure; for connectivity, rate-limit, or server errors, keep the token scope and let the controller retry. Reason `InvalidOrganization` means the Zero Trust organization returned an unusable auth domain.

Once the account is accepted, `status.verified.zones` lists the zones the token can see. Check that the zones in your grant appear there. [Troubleshooting](../operations/troubleshooting.md) covers the other conditions.

Next: [Expose a Service through Cloudflare Tunnel](expose-a-service.md).
