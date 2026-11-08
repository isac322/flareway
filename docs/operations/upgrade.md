# Upgrade and roll back Flareway

Upgrade CRDs before the controller. Helm installs files in a chart's `crds/` directory on first install but does not upgrade existing CRDs automatically.

## Before upgrading

1. Read the GitHub release notes for every version you skip, and compare chart values.
2. Confirm Gateway API v1.7.0 Standard CRDs are installed.
3. Back up Flareway custom resources and the values used for the current release.
4. Check for resources with `CleanupBlocked`, `Conflict`, or `Programmed=False`; resolve them before changing controller ownership.
5. Keep the old controller running until managed resource teardown or migration is complete.

## Version compatibility

| Flareway version | Gateway API Standard CRDs | Kubernetes API / client-go | Envoy data plane | cloudflared connector |
|---|---|---|---|---|
| `main` (unreleased) | v1.7.0 (backward-compatible with v1.6.x) | v1.37 (client-go v0.37.1) | `distroless-v1.40.0` | `2026.10.2` |
| `v0.3.3` | v1.6.3 | v1.37 (client-go v0.37.1) | `distroless-v1.39.3` | `2026.10.0` |
| `v0.1.0` - `v0.3.1` | v1.6.2 | v1.37 (client-go v0.37.0) | `distroless-v1.39.0` | `2026.9.0` |

A Flareway controller built for Gateway API v1.7.0 remains backward-compatible with clusters running Gateway API v1.6.x Standard CRDs for all v1.6.x resources and fields. Gateway API v1.7.0 Standard CRD features such as `HTTPRoute.spec.rules[].retry` require the v1.7.0 CRDs installed on the cluster.

Gateway API v1.7.0 `standard-install.yaml` includes the `safe-upgrades` `ValidatingAdmissionPolicy`. It blocks downgrading Gateway API CRDs to v1.6.x unless you delete that policy first.

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

Controller groups are an ownership boundary and also select the sweep targets and remote list calls. Before disabling a group:

1. Set affected remote objects to `managementPolicy: ObserveOnly`, or complete deletion while the controller still runs.
2. Wait for status to reflect the intended observed or deleted state.
3. Confirm no finalizer depends on that controller group.
4. Disable the group in the Helm values.

Disabling a group stops its reconcilers, removes its sweep targets and list calls, and leaves its objects unverified until the group is re-enabled. Re-enabling the group restores the reconcilers, sweep targets, and list calls. The sweep API budget counts only enabled targets. `DeviceSettings` and `ZeroTrustOrganization` are singleton APIs and are not sweep targets. No CRD or other schema migration is required for changing controller-group flags.

Re-enable the group before changing an object back to `Managed`. Never run two Flareway installations that manage the same Cloudflare object. See [Ownership, adoption, and teardown](../concepts/ownership-and-adoption.md) for how Flareway proves ownership.

## Image and chart pinning

Use an immutable chart version. The chart can pin the controller by digest:

```yaml
image:
  repository: ghcr.io/isac322/flareway
  tag: ""
  digest: sha256:<release-digest>
```

The `GatewayClassConfig` API defaults use cloudflared `2026.10.2` and CoreDNS `1.15.0` with digests, plus Envoy `distroless-v1.40.0` as a tag-only default. The chart's data-plane image references are digest-pinned, including Envoy's multi-arch index. Changing chart defaults does not rewrite an independently managed `GatewayClassConfig` unless Helm owns that object.

## Rollback

Do not roll back CRDs. Kubernetes CRD storage and served schemas must remain compatible with objects written by the newer controller.

A controller rollback is safe only when the older binary understands the stored resource version and fields. Roll back the chart, keep the newer CRDs, and watch conditions and Events for rejected fields or ownership conflicts:

```sh
helm history flareway --namespace flareway-system
helm rollback flareway <revision> --namespace flareway-system
```

If the older controller cannot reconcile the current objects, upgrade to the newer controller again instead of removing fields by hand. Flareway keeps traffic blocked when it cannot prove that Access, xDS, tunnel configuration, DNS, or private-network prerequisites are applied.
