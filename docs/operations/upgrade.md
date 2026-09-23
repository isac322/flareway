# Upgrade Flareway

Upgrade CRDs before the controller. Helm installs files in a chart's `crds/` directory on first install but does not upgrade existing CRDs automatically.

## Before upgrading

1. Read the release notes and compare chart values.
2. Confirm Gateway API v1.6.2 Standard CRDs are installed.
3. Back up Flareway custom resources and the values used for the current release.
4. Check for resources with `CleanupBlocked`, `Conflict`, or `Programmed=False`; resolve them before changing controller ownership.
5. Keep the old controller running until managed resource teardown or migration is complete.

For a released chart, inspect and apply its CRDs:

```sh
helm show crds oci://ghcr.io/isac322/charts/flareway \
  --version <release-version> \
  | kubectl apply --server-side -f -
```

For a checkout:

```sh
kubectl apply --server-side -f charts/flareway/crds/
```

Then upgrade the controller:

```sh
helm upgrade flareway oci://ghcr.io/isac322/charts/flareway \
  --version <release-version> \
  --namespace flareway-system \
  --reuse-values
```

Use `--reuse-values` only when the previous values remain valid. For a reviewed values file, prefer `--values flareway-values.yaml`.

## Logging output changes

The controller now defaults to production logging. Upgrading changes the log stream even with unchanged values:

- output changes from the console encoder to JSON lines on stderr;
- the default level changes from `debug` to `info`;
- multi-line console stacktraces become a single `stacktrace` field on JSON error entries;
- rare client-go (klog) text lines such as `I0923 ...` keep klog's own text format, unchanged from before; like gRPC's rare ERROR lines, they are not JSON;
- the per-request `Cloudflare API request completed` lines are `V(1)` and now require `logging.level=debug` (or `1`) to appear;
- the controller-runtime sampler applies: for each (level, message) pair the first 100 entries per second pass, then one in every 100. Debug/V(1), info, and error entries are all sampled; only `V(N)` with `N >= 2` bypasses it. Errors are degraded during bursts, never fully suppressed. The sampler is disabled by `logging.development=true` or an integer `logging.level` of `2` or higher.
- integer levels are limited to `1`–`6` in the chart schema. The raw `--zap-log-level` flag accepts larger integers, but levels `8` and higher make client-go log full API request and response bodies, including Secret contents; do not use them outside isolated debugging.

To restore the exact previous output (console encoder at `debug`, no sampling), set all three logging values — `logging.development=true` alone keeps JSON at `info` because explicit level and encoder override development defaults:

```sh
helm upgrade flareway oci://ghcr.io/isac322/charts/flareway \
  --version <release-version> \
  --namespace flareway-system \
  --reuse-values \
  --set logging.development=true \
  --set logging.level=debug \
  --set logging.encoder=console
```

For a Kustomize install, change the three `--zap-*` args in `config/manager/manager.yaml` to `--zap-devel=true`, `--zap-log-level=debug`, and `--zap-encoder=console`, or apply the equivalent JSON6902 patch in an overlay.

For local development, `go run ./cmd --zap-devel=true` restores console output at `debug`; no explicit level or encoder is needed there because no other zap flags are passed.

## Controller ownership changes

Controller toggles are an ownership boundary, not a performance setting. Before disabling a group:

1. Set affected remote objects to `managementPolicy: ObserveOnly`, or complete deletion while the controller still runs.
2. Wait for status to reflect the intended observed or deleted state.
3. Confirm no finalizer depends on that controller group.
4. Disable the group in the Helm values.

Re-enable the group before changing an object back to `Managed`. Never run two Flareway installations that manage the same Cloudflare object. Remote tags/comments, status remote IDs, and explicit `adoption.mode: AdoptById` prevent name-only takeover, but they do not turn concurrent writers into a supported configuration.

## Image and chart pinning

Use an immutable release version. The chart can pin the controller by digest:

```yaml
image:
  repository: ghcr.io/isac322/flareway
  tag: ""
  digest: sha256:<release-digest>
```

Gateway data-plane defaults are also pinned by the installed `GatewayClassConfig`: cloudflared `2026.9.1` by digest, Envoy `distroless-v1.39.1`, and CoreDNS `1.14.7` by digest. Changing chart defaults does not rewrite an independently managed `GatewayClassConfig` unless Helm owns that object.

## Rollback

Do not roll back CRDs. Kubernetes CRD storage and served schemas must remain compatible with objects written by the newer controller.

A controller rollback is safe only when the older binary understands the stored resource version and fields. Roll back the Deployment/chart, keep the newer CRDs, and watch conditions and Events for rejected fields or ownership conflicts.

```sh
helm history flareway --namespace flareway-system
helm rollback flareway <revision> --namespace flareway-system
```

If the old controller cannot reconcile the current objects, restore the newer controller instead of removing fields blindly. Flareway intentionally keeps traffic blocked when it cannot prove that Access, xDS, tunnel configuration, DNS, or private-network prerequisites are applied.
