# Install Flareway

Flareway requires Kubernetes Gateway API v1.6.2 Standard CRDs. The Helm chart installs Flareway's CRDs, controller, RBAC, xDS Service, and optional `GatewayClass` resources. It does not install Gateway API CRDs.

## Prerequisites

- A Kubernetes cluster supported by Gateway API v1.6.2.
- Helm 4.3 or a compatible Helm 3 client.
- A Cloudflare account and scoped API token for Cloudflare mode.
- A DNS zone in that account for public listeners.
- For private listeners, the WARP prerequisites in [troubleshooting.md](troubleshooting.md#private-warp-listeners).

Install Gateway API first:

```sh
kubectl apply --server-side \
  -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.6.2/standard-install.yaml
```

## Install from a checkout

The chart targets the fixed operator namespace `flareway-system`.

```sh
helm upgrade --install flareway ./charts/flareway \
  --namespace flareway-system \
  --create-namespace \
  --set gatewayClass.create=true
```

`gatewayClass.create` defaults to `false` so an install cannot silently take ownership of an existing `GatewayClass`. When enabled, the chart creates `GatewayClass/flareway` and `GatewayClassConfig/default`.

To install a released chart after it has been published:

```sh
helm upgrade --install flareway \
  oci://ghcr.io/isac322/charts/flareway \
  --version <release-version> \
  --namespace flareway-system \
  --create-namespace \
  --set gatewayClass.create=true
```

Set the Cloudflare account on the default class only after creating `CloudflareAccount`:

```sh
helm upgrade --install flareway ./charts/flareway \
  --namespace flareway-system \
  --set gatewayClass.create=true \
  --set gatewayClass.config.accountRefName=example
```

The complete application examples in [`config/samples/`](../../config/samples/) include the credential Secret, account grant, tunnel, Gateway API objects, and Access references. Replace every placeholder before applying them.

## Controller groups

All groups default to enabled. Disable a group only when another system owns every object in that area. The shared CloudflareAccount controller runs whenever any controller group is enabled.

| Value | Controllers |
|---|---|
| `controllers.gateway` | GatewayClass, Gateway, CloudflareTunnel |
| `controllers.access` | AccessApplication, AccessStandaloneApplication, AccessInfrastructureTarget, AccessCustomPage, AccessPolicy, AccessGroup, IdentityProvider, DevicePostureRule, DevicePostureIntegration, ServiceToken |
| `controllers.privateNetwork` | VirtualNetwork, NetworkRoute, HostnameRoute, WARPConnector |
| `controllers.device` | DeviceProfile, DeviceSettings |
| `controllers.organization` | ZeroTrustOrganization, ZeroTrustGatewayPolicy, ZeroTrustList |


## Namespace ownership

`namespace.create` defaults to `false`; use Helm's `--create-namespace` for the normal installation. If a platform release renders the Namespace through this chart, set `namespace.create=true`, run the release from an existing Helm release namespace, and do not also pass `--create-namespace` for `flareway-system`. The rendered Namespace has `helm.sh/resource-policy: keep`.

Flareway CRDs remain after `helm uninstall`, following Helm's CRD lifecycle. Workload data planes and remote Cloudflare objects follow each resource's finalizer and `deletionPolicy`; uninstalling the controller before those finalizers finish can leave cleanup pending. Delete managed application resources first, wait for teardown, and uninstall the chart last.

## Conformance-only installation

Conformance mode excludes Cloudflare Tunnel, DNS, Access, and WARP. It is for Gateway API validation, not production ingress.

```sh
helm upgrade --install flareway ./charts/flareway \
  --namespace flareway-system \
  --create-namespace \
  --set gatewayClass.create=true \
  --set gatewayClass.config.conformanceMode=true \
  --set gatewayClass.config.accountRefName=
```

See the [conformance report README](../../conformance/reports/v1.6.2/flareway/README.md) for the tested workflow.
