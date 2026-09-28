# Flareway Helm chart values

The chart at `oci://ghcr.io/isac322/charts/flareway` installs the controller, RBAC, Services, NetworkPolicies, and Flareway CRDs, but not Gateway API CRDs.

Print every default with `helm show values oci://ghcr.io/isac322/charts/flareway --version <chart-version>`. `helm show chart oci://ghcr.io/isac322/charts/flareway` prints the latest `version`; release notes are on GitHub Releases. For installation steps, see the [install guide](https://flareway.bhyoo.com/docs/get-started/install/).

## CRDs

The chart packages every generated `flareway.bhyoo.com` CRD in `crds/`. Print them with `helm show crds oci://ghcr.io/isac322/charts/flareway --version <chart-version>`.

Helm installs files from `crds/` before the chart templates. Helm does not upgrade or delete those CRDs during a normal chart upgrade or uninstall; the [upgrade guide](https://flareway.bhyoo.com/docs/operations/upgrade/) applies them first. The chart has no uninstall hooks and does not contact Cloudflare or delete remote resources during uninstall.

## Controller groups

All controller groups default to enabled. The values map directly to the controller-manager feature flags rendered by the Deployment. The shared `CloudflareAccount` controller runs whenever any controller group is enabled.

| Value | Controller flag | Reconcilers |
|---|---|---|
| `controllers.gateway` | `--enable-gateway-controllers` | `GatewayClass`, `Gateway`, `CloudflareTunnel` |
| `controllers.access` | `--enable-access-controllers` | `AccessApplication`, `AccessStandaloneApplication`, `AccessInfrastructureTarget`, `AccessCustomPage`, `AccessPolicy`, `AccessGroup`, `IdentityProvider`, `DevicePostureRule`, `DevicePostureIntegration`, `ServiceToken` |
| `controllers.privateNetwork` | `--enable-private-network-controllers` | `VirtualNetwork`, `NetworkRoute`, `HostnameRoute`, `WARPConnector` |
| `controllers.device` | `--enable-device-controllers` | `DeviceProfile`, `DeviceSettings` |
| `controllers.organization` | `--enable-organization-controllers` | `ZeroTrustOrganization`, `ZeroTrustGatewayPolicy`, `ZeroTrustList` |

`WARPConnector` follows `controllers.privateNetwork`; it has no independent chart switch. The installed ClusterRole includes the permissions required by every controller group, including each resource's main, status, and finalizer subresources.

Disabling a group changes which controller owns remote objects. Follow the [controller group steps](https://flareway.bhyoo.com/docs/operations/upgrade/#changing-controller-groups) before turning one off.

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
| `logging.development` | `false` | Run the controller logger in development mode (`--zap-devel`). |
| `logging.level` | `info` | Controller log level (`--zap-log-level`). |
| `logging.encoder` | `json` | Controller log encoder (`--zap-encoder`). |
| `reconcile.driftPolicy` | `Overwrite` | Reaction to out-of-band Cloudflare changes (`--drift-policy`). |
| `reconcile.freshness.authz` | `60s` | Read-skip TTL for T1 (Access) kinds (`--freshness-authz`). |
| `reconcile.freshness.traffic` | `300s` | Read-skip TTL for T2 (traffic-path) kinds (`--freshness-traffic`). |
| `reconcile.freshness.indirect` | `1800s` | Read-skip TTL for T3 (device and organization) kinds (`--freshness-indirect`). |
| `reconcile.freshness.display` | `0s` | Read-skip TTL for T4 display-only reads (`--freshness-display`). |
| `reconcile.disableSweep` | `false` | Stop the periodic drift sweep worker (`--disable-sweep`). |
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
| `gatewayClass.config.scheduling` | `{}` | Dataplane pod placement (`nodeSelector`, `tolerations`, `affinity`, `topologySpreadConstraints`) rendered into the `GatewayClassConfig`. |

`helm show values` lists pod placement, security context, resources, Service annotations, and the complete `GatewayClassConfig` defaults. The top-level `nodeSelector`, `tolerations`, `affinity`, and `topologySpreadConstraints` values place only the controller-manager pod; dataplane pods are placed through `gatewayClass.config.scheduling`.

## Drift detection and freshness

The `reconcile` values map to the manager's drift and freshness flags and are rendered unconditionally after the controller group flags. Their defaults match the manager's built-in defaults.

| Value | Flag | Accepted values |
|---|---|---|
| `reconcile.driftPolicy` | `--drift-policy` | `Overwrite` restores the desired state over an out-of-band change. `Hold` reports the drift and skips the remote write until the spec changes or the remote is repaired. |
| `reconcile.freshness.authz` | `--freshness-authz` | Duration; applies to `AccessApplication`, `AccessStandaloneApplication`, `AccessPolicy`, `AccessGroup`, `AccessCustomPage`, `AccessInfrastructureTarget`, `ServiceToken`, `IdentityProvider` |
| `reconcile.freshness.traffic` | `--freshness-traffic` | Duration; applies to `CloudflareTunnel`, DNS records, `ZeroTrustGatewayPolicy`, `ZeroTrustList`, `VirtualNetwork`, `NetworkRoute`, `HostnameRoute` |
| `reconcile.freshness.indirect` | `--freshness-indirect` | Duration; applies to `DeviceProfile`, `DeviceSettings`, `DevicePostureRule`, `DevicePostureIntegration`, `ZeroTrustOrganization`, `WARPConnector` |
| `reconcile.freshness.display` | `--freshness-display` | Duration; no Flareway kind uses the T4 grade |
| `reconcile.disableSweep` | `--disable-sweep` | `true` or `false` |

A freshness value is how long a converged object skips Cloudflare reads. The schema accepts a whole number followed by `ms`, `s`, `m`, or `h`, such as `90s` or `30m`. `0s` keeps that grade's gate closed, so its objects read Cloudflare on every pass. The manager exits at startup unless the positive values satisfy `authz` ≤ `traffic` ≤ `indirect`; the schema does not check that ordering.

With `reconcile.disableSweep=true`, freshness gates keep working, and out-of-band drift is detected only when an object's TTL expires.

```sh
helm upgrade flareway oci://ghcr.io/isac322/charts/flareway \
  --version <chart-version> \
  --namespace flareway-system \
  --reuse-values \
  --set reconcile.driftPolicy=Hold \
  --set reconcile.freshness.traffic=120s
```

For grades, the sweep, detection bounds, and API budget, see [Drift detection and Cloudflare API budget](https://flareway.bhyoo.com/docs/operations/freshness-and-drift/).

## Logging

The controller logs JSON lines to stderr at `info` level, and error entries carry a `stacktrace` field. Three values map to the manager's zap flags and are rendered unconditionally at the end of the manager args:

| Value | Flag | Accepted values |
|---|---|---|
| `logging.development` | `--zap-devel` | `true` or `false` |
| `logging.level` | `--zap-log-level` | `debug`, `info`, `error`, `panic`, or an integer `1`–`6` (logr `V(N)` verbosity) |
| `logging.encoder` | `--zap-encoder` | `json` or `console` |

`warn` is not an accepted level; the flag parser and the values schema both reject it.

An explicit `logging.level` or `logging.encoder` always overrides the development-mode defaults. `logging.development=true` alone therefore keeps JSON output at `info` and switches only development semantics: no sampling, warn-level stacktraces, full object dumps, and panics on DPanic entries. For human-readable console output at `debug`, set all three:

```sh
helm upgrade flareway oci://ghcr.io/isac322/charts/flareway \
  --version <chart-version> \
  --namespace flareway-system \
  --reuse-values \
  --set logging.development=true \
  --set logging.level=debug \
  --set logging.encoder=console
```

In production mode the controller-runtime sampler applies: for each (level, message) pair the first 100 entries per second pass, then one in every 100. Debug/V(1), info, and error entries are all sampled; only `V(N)` with `N >= 2` bypasses it. Bursts thin out error entries but never suppress them fully. `logging.development=true` or an integer `logging.level` of `2` or higher disables the sampler; `logging.level=debug` does not.

Two kinds of line do not use the configured format. Rare client-go (klog) lines, such as `HTTP2 has been explicitly disabled` or invalid `HTTP2_*` environment warnings, keep klog's own text format (`I0923 12:00:00.000000 1 file.go:123] msg`). gRPC's own logger may also print rare ERROR-severity text lines (`YYYY/MM/DD hh:mm:ss ERROR: ...`). Neither is JSON.

The chart schema caps integer levels at `6`. The raw `--zap-log-level` flag accepts larger integers, but levels `8` and higher make client-go log API request and response bodies (truncated to 1024 bytes at `8` and 10240 bytes at `9`, complete from `10`), including Secret contents. Do not use them outside isolated debugging.

The chart exposes only these three logging values; other zap options such as stacktrace level, time encoding, or extra args are not configurable through the chart.

For filtering JSON logs and reading debug output, see [Troubleshooting](https://flareway.bhyoo.com/docs/operations/troubleshooting/#debug-logging).
