# Flareway Helm chart

This chart installs the Flareway controller manager, its RBAC, Services, NetworkPolicies, and generated Flareway CRDs. Gateway API CRDs are a separate prerequisite.

## CRDs

The chart packages every generated `flareway.bhyoo.com` CRD in `crds/`, including:

- `AccessStandaloneApplication`
- `AccessCustomPage`
- `AccessInfrastructureTarget`
- `DevicePostureIntegration`
- `WARPConnector`

Helm installs files from `crds/` before the chart templates. Helm does not upgrade or delete those CRDs during a normal chart upgrade or uninstall. The chart has no uninstall hooks and does not contact Cloudflare or delete remote resources during uninstall.

## Controller groups

All controller groups default to enabled. The values map directly to the controller-manager feature flags rendered by the Deployment. The shared `CloudflareAccount` controller runs whenever any controller group is enabled.

| Value | Controller flag | Reconcilers |
|---|---|---|
| `controllers.gateway` | `--enable-gateway-controllers` | `GatewayClass`, `Gateway`, `CloudflareTunnel` |
| `controllers.access` | `--enable-access-controllers` | `AccessApplication`, `AccessStandaloneApplication`, `AccessInfrastructureTarget`, `AccessCustomPage`, `AccessPolicy`, `AccessGroup`, `IdentityProvider`, `DevicePostureRule`, `DevicePostureIntegration`, `ServiceToken` |
| `controllers.privateNetwork` | `--enable-private-network-controllers` | `VirtualNetwork`, `NetworkRoute`, `HostnameRoute`, `WARPConnector` |
| `controllers.device` | `--enable-device-controllers` | `DeviceProfile`, `DeviceSettings` |
| `controllers.organization` | `--enable-organization-controllers` | `ZeroTrustOrganization`, `ZeroTrustGatewayPolicy`, `ZeroTrustList` |

`WARPConnector` follows `controllers.privateNetwork`; it does not have an independent chart switch. The installed ClusterRole includes the permissions required by every supported controller group, including each new resource's main, status, and finalizer subresources.

## Tunnel runtime settings

Tunnel configuration mode and management-token issuance are resource-level settings, not chart-level runtime defaults:

- `CloudflareTunnel.spec.configuration.mode` defaults to `Gateway` when omitted. Set it to `Direct` explicitly for a tunnel whose configuration is owned by the `CloudflareTunnel` reconciler rather than a `Gateway`.
- `CloudflareTunnel.spec.managementToken` is optional and opt-in. When requested, Flareway writes the issued token only to the tunnel-owned Secret referenced from status.

The chart therefore does not expose global Direct-mode or management-token values.

## Main values

| Value | Default | Description |
|---|---:|---|
| `namespace.create` | `false` | Render the fixed operator Namespace. |
| `namespace.name` | `flareway-system` | Operator namespace used by the controller and data plane. |
| `image.repository` | `ghcr.io/isac322/flareway` | Controller image repository. |
| `image.tag` | `""` | Controller image tag; the chart `appVersion` is used when empty. |
| `image.digest` | `""` | Optional image digest, which takes precedence over the tag. |
| `goRuntime.GOMEMLIMIT` | `115MiB` | Set the Go runtime soft memory limit for the controller. |
| `goRuntime.GODEBUG` | `tracebacklabels=0` | Disable goroutine labels in Go tracebacks. |
| `controllers.gateway` | `true` | Enable the Gateway and account controller group. |
| `controllers.access` | `true` | Enable the Access controller group. |
| `controllers.privateNetwork` | `true` | Enable private-network and WARP Connector controllers. |
| `controllers.device` | `true` | Enable device settings and profile controllers. |
| `controllers.organization` | `true` | Enable Zero Trust organization and Gateway policy controllers. |
| `leaderElection.enabled` | `true` | Enable controller-manager leader election. |
| `metrics.enabled` | `true` | Expose the metrics port and Service. |
| `metrics.secure` | `true` | Serve metrics over HTTPS with Kubernetes authorization. |
| `xds.service.port` | `18000` | Delta ADS and SDS service port. |
| `networkPolicy.enabled` | `true` | Render controller ingress NetworkPolicies. |
| `gatewayClass.create` | `false` | Create the chart-managed `GatewayClass` and `GatewayClassConfig`. |
| `gatewayClass.config.accountRefName` | `""` | Default cluster-scoped `CloudflareAccount` reference. |
| `gatewayClass.config.conformanceMode` | `false` | Run the generated Gateway class without Cloudflare integration. |

See `values.yaml` for pod placement, security context, resources, Service annotations, and complete `GatewayClassConfig` defaults.
