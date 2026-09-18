# Flareway fact map

Project facts for the README evidence brief. Paths below are
repository-root-relative; links are relative to this file. Load this before
drafting — every README claim must trace to one of these sources. This map
is a dated snapshot (2026-09-18): refresh it against the repository before
reuse — versions, defaults, and doc paths drift. Apply the
repository invariants in [`../../../rules/flareway-invariants.md`](../../../rules/flareway-invariants.md)
rather than restating them.

## Identity and selected assets

- Main line (exact): **A Kubernetes operator for Cloudflare Tunnel, Access &
  WARP.**
- User-selected brand assets: the **D2** mark with **T3** typography for the
  logo, and the **M2** wording for the main line above.
  - Logo: [`assets/cloud-gateway/d2/logo-t3.svg`](../../../../assets/cloud-gateway/d2/logo-t3.svg)
  - Architecture diagrams, both bound to this fact map:
    [`assets/architecture/layers-light.svg`](../../../../assets/architecture/layers-light.svg)
    with its dark counterpart `layers-dark.svg` (four layers: clients,
    Cloudflare edge, one outbound tunnel through a sealed cluster boundary,
    the Kubernetes data plane), and
    [`assets/architecture/topology.svg`](../../../../assets/architecture/topology.svg)
    (the same system in Kubernetes-object terms). Embed the layered pair with
    `<picture>` so dark mode switches; link the topology rather than
    embedding a second hero image.
  - Every diagram must keep the product concept legible: one sealed cluster
    boundary, one blocked inbound marker, a single outbound tunnel opened by
    `cloudflared`, and the public/private split beyond the edge.

## Maturity — state it, never soften it

- `Status: experimental`, API version `v1alpha1`; not production ingress.
- The controller runs a **single replica with serialized reconciliation** —
  never let this read as HA.
- Under live verification: whether the edge accepts a `127.0.0.1` answer for
  private hostnames, and long-streaming limits.
- Conformance: local `dev` run on kind — GatewayHTTP Core 37/37, claimed
  Extended 30/30 — under `conformanceMode`, which disables Cloudflare
  Tunnel, DNS, Access, and WARP. It validates Envoy behavior, not the edge
  path. The report lists 13 unsupported features (e.g. `ListenerSet`,
  `HTTPRouteRetry`). Source:
  [`conformance/reports/v1.6.2/flareway/README.md`](../../../../conformance/reports/v1.6.2/flareway/README.md).

## Architecture (smallest accurate model)

- A `Gateway` maps to one `CloudflareTunnel` and one data-plane Deployment
  with three containers:
  - `cloudflared` — outbound QUIC/HTTP2 to Cloudflare's edge; no inbound
    ports or public IPs.
  - Envoy — receives decrypted traffic over loopback; L7 routing streamed
    over xDS (Delta ADS): path/header/query/method matching, rewrites,
    weighted backends; verifies `Cf-Access-Jwt-Assertion` via `jwt_authn`
    when an Access application attaches (GEP-713 policy attachment).
  - CoreDNS sidecar — resolves private hostnames to `127.0.0.1` so WARP
    traffic flows through Envoy.
- Public listeners get proxied CNAMEs to the tunnel hostname with an
  ownership comment; private listeners terminate TLS at Envoy over
  Cloudflare private network routes.
- `CloudflareTunnel` also has a Direct mode owning the full remote
  `cloudflared` config for non-Gateway services (TCP, SSH, RDP, bastion).
- An ASCII diagram is sufficient; no extra diagram assets needed.
- Full model: [`docs/design/001-cloudflare-gateway-api-integration.md`](../../../../docs/design/001-cloudflare-gateway-api-integration.md).

## Capabilities

22 CRDs in `flareway.bhyoo.com/v1alpha1`, four groups — Gateway & account
(`GatewayClassConfig`, `CloudflareAccount`, `CloudflareTunnel`), Access (10
kinds), private networking (`VirtualNetwork`, `NetworkRoute`,
`HostnameRoute`, `WARPConnector`), account-wide settings (5 kinds). List
groups, not the full inventory; the schema source of truth is
`config/crd/bases/` and [`docs/api-reference.md`](../../../../docs/api-reference.md).

## First safe action and install path

- Safe first action: render manifests locally — `helm template` or
  `helm upgrade --install --dry-run` against the checkout chart
  `./charts/flareway`. A rendered-manifest path plus an explicit install
  link is an acceptable first task for an experimental operator; a live
  install is not obligatory.
- Real install prerequisites: Gateway API **v1.6.2 Standard** CRDs applied
  first (the chart does not install them), Helm 4.3/compatible, a Cloudflare
  account + scoped API token, a DNS zone for public listeners, WARP
  prerequisites for private listeners.
- Namespace is fixed `flareway-system`; `namespace.create` defaults `false`
  → use `--create-namespace`. `gatewayClass.create` defaults `false` →
  `--set gatewayClass.create=true` (prevents silently taking an existing
  GatewayClass).
- Set `gatewayClass.config.accountRefName` only **after** the
  `CloudflareAccount` CR exists.
- Never invite applying `config/samples/workload_application.yaml` blindly:
  it contains placeholders (API token, account ID, hostnames, IdP/policy
  IDs) that must be replaced first.
- OCI chart: `oci://ghcr.io/isac322/charts/flareway` — published "after it
  has been published"; do not invent a release tag.
- Source: [`docs/operations/install.md`](../../../../docs/operations/install.md).

## Security model (one paragraph, link for detail)

Two authorization layers must both allow: Kubernetes RBAC and
`CloudflareAccount.spec.grants` (namespaces, hostnames, zones, exposures).
Fail-closed on denial; explicit `AdoptById` adoption for existing remote
objects; credentials in Secrets, never in status; `Programmed` only after
edge DNS, tunnel sessions, xDS, and the data plane converge. Detail:
[`docs/operations/rbac-token.md`](../../../../docs/operations/rbac-token.md).

## Documentation links that exist

- [`docs/operations/install.md`](../../../../docs/operations/install.md) —
  install
- [`docs/operations/upgrade.md`](../../../../docs/operations/upgrade.md) —
  upgrade
- [`docs/operations/rbac-token.md`](../../../../docs/operations/rbac-token.md)
  — RBAC and API tokens
- [`docs/operations/troubleshooting.md`](../../../../docs/operations/troubleshooting.md)
  — troubleshooting
- [`docs/api-reference.md`](../../../../docs/api-reference.md) and
  [`docs/api/README.md`](../../../../docs/api/README.md) — API reference
- [`docs/design/001-cloudflare-gateway-api-integration.md`](../../../../docs/design/001-cloudflare-gateway-api-integration.md)
  — design document
- [`conformance/reports/v1.6.2/flareway/README.md`](../../../../conformance/reports/v1.6.2/flareway/README.md)
  — conformance report
- [`config/samples/`](../../../../config/samples/) — example manifests

## License and maintenance

Apache License 2.0, Copyright 2026 Byeonghoon Yoo —
[`LICENSE`](../../../../LICENSE). Contributor/help information comes only
from existing metadata and docs; no fabricated Slack/Discord/contact
channels.

## Claims not to make

- No production-ready, HA, or multi-replica implications.
- No universal/100% conformance, zero-cost, or performance guarantees.
- No "latest released chart" assertion or invented release tags.
- No silent widening of supported mode boundaries (Gateway vs Direct).
- No edge-path conformance claims — conformanceMode is Envoy-only.
