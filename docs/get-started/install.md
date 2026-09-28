# Install Flareway from the OCI Helm chart

Install Flareway from `oci://ghcr.io/isac322/charts/flareway` on a cluster with Gateway API v1.6.2 CRDs, then add a Cloudflare account, token, and zone.

## Preview the manifests without a cluster

Rendering the chart needs no cluster and no Cloudflare credentials, so you can read what an install creates before anything runs:

```sh
helm template flareway oci://ghcr.io/isac322/charts/flareway \
  --namespace flareway-system \
  --set gatewayClass.create=true \
  --set gatewayClass.config.accountRefName=example-account
```

The output contains the controller Deployment and its ServiceAccount, the RBAC objects (three ClusterRoles, two ClusterRoleBindings, a Role, and a RoleBinding), the metrics and xDS Services, and three NetworkPolicies. The two `gatewayClass` values add `GatewayClass/flareway` and a `GatewayClassConfig/default` that names the `example-account` CloudflareAccount; [Connect a Cloudflare account](connect-cloudflare.md) sets the same values on a real cluster. Add `--include-crds` to print the Flareway CRDs as well.

## Prerequisites

- A Kubernetes cluster supported by Gateway API v1.6.2.
- Helm 4.3 or a compatible Helm 3 client.
- A Cloudflare account and a scoped API token. [Connect a Cloudflare account](connect-cloudflare.md) lists the token capabilities.
- A DNS zone in that account for public listeners.
- For private listeners, the WARP prerequisites in [Reach private Services over Cloudflare WARP](private-services-over-warp.md).

## Install the Gateway API CRDs

The Flareway chart does not bundle Gateway API CRDs. Install the v1.6.2 Standard channel first:

```sh
kubectl apply --server-side \
  -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.6.2/standard-install.yaml
```

## Install the chart

The chart installs Flareway's CRDs, the controller, its RBAC, and the xDS Service into the fixed operator namespace `flareway-system`:

```sh
helm upgrade --install flareway oci://ghcr.io/isac322/charts/flareway \
  --version <chart-version> \
  --namespace flareway-system \
  --create-namespace
```

`helm show chart oci://ghcr.io/isac322/charts/flareway` prints the latest `version`; release notes are on GitHub Releases.

This install creates no `GatewayClass`. `gatewayClass.create` defaults to `false` so that an install cannot silently take ownership of an existing `GatewayClass`, and a `GatewayClassConfig` must name a `CloudflareAccount` unless it runs in conformance mode. You create `GatewayClass/flareway` and `GatewayClassConfig/default` in [Connect a Cloudflare account](connect-cloudflare.md), after the account exists.

## Verify the installation

```sh
kubectl -n flareway-system rollout status deployment/flareway-controller-manager
```

The rollout finishes when the controller is ready.

## Controller groups

All controller groups default to enabled. The shared `CloudflareAccount` controller runs whenever any group is enabled.

| Value | Controllers |
|---|---|
| `controllers.gateway` | GatewayClass, Gateway, CloudflareTunnel |
| `controllers.access` | AccessApplication, AccessStandaloneApplication, AccessInfrastructureTarget, AccessCustomPage, AccessPolicy, AccessGroup, IdentityProvider, DevicePostureRule, DevicePostureIntegration, ServiceToken |
| `controllers.privateNetwork` | VirtualNetwork, NetworkRoute, HostnameRoute, WARPConnector |
| `controllers.device` | DeviceProfile, DeviceSettings |
| `controllers.organization` | ZeroTrustOrganization, ZeroTrustGatewayPolicy, ZeroTrustList |

Disable a group only when another system owns every object in that area. A controller group is an ownership boundary; see [Ownership and adoption](../concepts/ownership-and-adoption.md). [Helm chart values](../../charts/flareway/README.md) lists every other setting.

## Namespace ownership

`namespace.create` defaults to `false`; use Helm's `--create-namespace` for a normal installation. If a platform release renders the Namespace through this chart, set `namespace.create=true`, run the release from an existing Helm release namespace, and do not also pass `--create-namespace` for `flareway-system`. The rendered Namespace has `helm.sh/resource-policy: keep`.

## Uninstall

Delete the managed application resources first and wait for their finalizers to finish teardown, then run `helm uninstall flareway --namespace flareway-system`. Helm keeps the Flareway CRDs and the `flareway-system` namespace, and uninstalling the chart never contacts Cloudflare or deletes remote objects; [Ownership and adoption](../concepts/ownership-and-adoption.md) explains the teardown order.

Next: [Connect a Cloudflare account](connect-cloudflare.md).
