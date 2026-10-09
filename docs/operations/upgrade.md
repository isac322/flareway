# Upgrade and roll back Flareway

Upgrade CRDs before the controller. Helm installs files in a chart's `crds/` directory on first install but does not upgrade existing CRDs automatically.

## Before upgrading

1. Read the GitHub release notes for every version you skip, and compare chart values.
2. Confirm Gateway API v1.6.3 Standard CRDs are installed.
3. Back up Flareway custom resources and the values used for the current release.
4. Check for resources with `CleanupBlocked`, `Conflict`, or `Programmed=False`; resolve them before changing controller ownership.
5. Keep the old controller running until managed resource teardown or migration is complete.

## Apply the CRDs first

Apply the CRDs from the chart version you are upgrading to:

```sh
helm show crds oci://ghcr.io/isac322/charts/flareway \
  --version <chart-version> \
  | kubectl apply --server-side -f -
```

`helm show chart oci://ghcr.io/isac322/charts/flareway` prints the latest `version`; release notes are on GitHub Releases.

## Upgrade the controller

```sh
helm upgrade flareway oci://ghcr.io/isac322/charts/flareway \
  --version <chart-version> \
  --namespace flareway-system \
  --values flareway-values.yaml
```

Prefer a reviewed values file. Use `--reuse-values` instead only when the values of the current release remain valid for the new chart.

## Changing controller groups

Controller groups are an ownership boundary. Before disabling a group:

1. Set affected remote objects to `managementPolicy: ObserveOnly`, or complete deletion while the controller still runs.
2. Wait for status to reflect the intended observed or deleted state.
3. Confirm no finalizer depends on that controller group.
4. Disable the group in the Helm values.

Re-enable the group before changing an object back to `Managed`. Never run two Flareway installations that manage the same Cloudflare object. See [Ownership, adoption, and teardown](../concepts/ownership-and-adoption.md) for how Flareway proves ownership.

## Image and chart pinning

Use an immutable chart version. The chart can pin the controller by digest:

```yaml
image:
  repository: ghcr.io/isac322/flareway
  tag: ""
  digest: sha256:<release-digest>
```

The installed `GatewayClassConfig` pins the Gateway data-plane images, each by digest: cloudflared `2026.10.0`, Envoy `distroless-v1.39.3`, and CoreDNS `1.14.7`. Changing chart defaults does not rewrite an independently managed `GatewayClassConfig` unless Helm owns that object.

## Rollback

Do not roll back CRDs. Kubernetes CRD storage and served schemas must remain compatible with objects written by the newer controller.

A controller rollback is safe only when the older binary understands the stored resource version and fields. Roll back the chart, keep the newer CRDs, and watch conditions and Events for rejected fields or ownership conflicts:

```sh
helm history flareway --namespace flareway-system
helm rollback flareway <revision> --namespace flareway-system
```

If the older controller cannot reconcile the current objects, upgrade to the newer controller again instead of removing fields by hand. Flareway keeps traffic blocked when it cannot prove that Access, xDS, tunnel configuration, DNS, or private-network prerequisites are applied.
