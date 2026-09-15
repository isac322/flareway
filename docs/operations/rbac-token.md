# RBAC and Cloudflare API tokens

Flareway uses two independent authorization layers:

1. Kubernetes RBAC controls which cluster resources the controller can read or write.
2. `CloudflareAccount.spec.grants` controls which namespaces, hostnames, zones, exposures, backends, policy references, and private-route objects may use a Cloudflare account.

Both layers must allow an operation. Flareway fails closed when either layer denies it.

## Cloudflare API token

Create a scoped API token for each `CloudflareAccount`; do not use the Global API Key. Grant only the capabilities required by the enabled controllers and resources.

| Feature | Required Cloudflare capability |
|---|---|
| Account verification | Read account, zones, token verification, and Zero Trust organization metadata |
| Managed tunnels | Read/write Cloudflare Tunnels, tunnel tokens, and tunnel configurations |
| Managed public DNS | Read zones and read/write DNS records for the granted zones |
| Access | Read/write Access applications, reusable policies, groups, identity providers, posture rules, and service tokens used by the installation |
| Private network | Read/write virtual networks, CIDR routes, and private hostname routes |
| Device settings | Read/write device profiles, split-tunnel lists, fallback domains, and device settings |
| Organization | Read/write Zero Trust organization settings, Gateway rules, and Gateway lists |

Cloudflare's dashboard permission labels may group these API families differently. Start with a token limited to the target account and zones, then inspect `CloudflareAccount.status.conditions` and `status.verified.tokenPermissions`. Add a permission only when the controller reports the missing capability.

Store the token in the namespace named by `apiTokenSecretRef`; the normal location is `flareway-system`:

```sh
kubectl -n flareway-system create secret generic cloudflare-api-token \
  --from-literal=token='<scoped-token>'
```

Reference one key explicitly:

```yaml
apiVersion: flareway.bhyoo.com/v1alpha1
kind: CloudflareAccount
metadata:
  name: example
spec:
  accountId: "00000000000000000000000000000000"
  credentials:
    apiTokenSecretRef:
      name: cloudflare-api-token
      namespace: flareway-system
      key: token
  grants: []
```

The controller never writes API tokens to status, Events, or request logs. Tunnel connector tokens, Access AUD values, and service-token client secrets are also stored only in Kubernetes Secrets.

## Account grants

A namespace that matches no grant is denied. Keep grants narrow:

```yaml
grants:
- namespaceSelector:
    matchLabels:
      kubernetes.io/metadata.name: application-team
  hostnames:
  - api.example.com
  zones:
  - example.com
  exposures:
  - Public
  unprotectedHostnames: []
  accessPolicyRefs: Allowed
  backends:
    namespaces: Same
    kinds:
    - Service
  platformObjects: Denied
```

`unprotectedHostnames` is a security boundary. Add a hostname only when the platform intends to serve at least one route without Access. Mixed protected/public path carve-outs require this grant even though the protected parent path remains guarded.

`platformObjects: Allowed` permits tenant-driven management of platform-scoped private-network objects. Leave it `Denied` unless the namespace is trusted to create those objects.

## Kubernetes RBAC

The chart grants the controller access to:

- Gateway API resources and their status subresources;
- Flareway CRDs, status, and finalizers;
- Secrets used for Cloudflare credentials, tunnel tokens, xDS certificates, Access AUDs, listener certificates, and service tokens;
- Deployments, Services, ConfigMaps, PodDisruptionBudgets, NetworkPolicies, Pods, EndpointSlices, Namespaces, Events, and leader-election Leases.

The controller ServiceAccount is cluster-scoped because `GatewayClass`, `GatewayClassConfig`, `CloudflareAccount`, namespace grants, cross-namespace backend authorization, and Gateway API watches cross namespace boundaries. Do not bind the controller's ClusterRole to tenant users.

Tenant RBAC should separate duties:

- application teams may manage `Gateway` and `HTTPRoute` in their namespaces;
- security teams may manage `AccessApplication` and namespaced Access references;
- platform teams should own `CloudflareAccount`, account grants, global settings, and shared private-network resources;
- only secret administrators should read credential, AUD, tunnel-token, or service-token Secrets.
