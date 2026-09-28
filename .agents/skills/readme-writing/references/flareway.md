# Flareway fact map

Project facts for the README evidence brief. Paths below are
repository-root-relative; links are relative to this file. Load this before
drafting — every README claim must trace to one of these sources. This map
is a dated snapshot (2026-09-28): refresh it against the repository before
reuse — versions, defaults, and doc paths drift. Apply the
repository invariants in [`../../../rules/flareway-invariants.md`](../../../rules/flareway-invariants.md)
rather than restating them.

The README is also the site's `/docs/` Overview page (synced by
`site/scripts/sync-docs.ts`). Its H1 becomes the page `<title>` (keep it
≤ 49 characters) and its first plain paragraph after the H1 becomes the meta
description (keep it ≤ 155 characters, plain prose, not a list or image).

## Identity and selected assets

- H1: **Flareway: Gateway API on Cloudflare Tunnel.**
- First paragraph: what Flareway is (a Kubernetes operator), that a `Gateway`
  becomes a Cloudflare Tunnel with no inbound ports, that `HTTPRoute` rules
  run in Envoy, and that Access is verified.
- Brand line used on the landing page: "A Gateway that becomes a Cloudflare
  Tunnel."
- User-selected brand assets: the **D2** mark with **T3** typography for the
  logo.
  - Logo: [`assets/cloud-gateway/d2/logo-t3.svg`](../../../../assets/cloud-gateway/d2/logo-t3.svg).
    The sync drops this exact line from the Overview page; keep it on its own
    line in that form.
  - Architecture diagrams:
    [`assets/architecture/layers-light.svg`](../../../../assets/architecture/layers-light.svg)
    with its dark counterpart `layers-dark.svg` (four layers: clients,
    Cloudflare edge, an outbound tunnel through a sealed cluster boundary,
    the Kubernetes data plane), and
    [`assets/architecture/topology.svg`](../../../../assets/architecture/topology.svg)
    (the same system in Kubernetes-object terms). The README embeds the
    layered pair with `<picture>` so dark mode switches;
    `docs/concepts/how-it-works.md` embeds both.
  - Every diagram must keep the product concept legible: one sealed cluster
    boundary, one blocked inbound marker, outbound connections opened by
    `cloudflared`, and the public/private split beyond the edge.

## Selling points (in this order)

1. Full HTTPRoute routing behind the tunnel — method, header, and query
   matches, rewrites, redirects, mirroring, timeouts, CORS, and weighted
   splits run in Envoy; `cloudflared` ingress rules alone match only hostname
   and an unanchored path regex.
2. Access enforced at the edge and origin — an `AccessApplication` creates the
   Cloudflare Access application and policy; the Access JWT is verified again
   at the origin by `cloudflared` and Envoy for public hostnames and by Envoy
   for private ones.
3. Private services over WARP, same Gateway — `exposure: Private` listeners,
   Envoy terminates TLS with your certificate. Caveat: live edge acceptance of
   the `127.0.0.1` private-hostname answer is unverified.
4. Fails closed on shared clusters — Kubernetes RBAC and
   `CloudflareAccount.spec.grants` must both allow; deleting a policy never
   makes a protected route public; `AdoptById` is required to take over an
   existing object; `Programmed` only after edge DNS, tunnel sessions, xDS,
   and Envoy converge.

## Status and scope — state as design, not as a warning

- API version `v1alpha1` (state it only as the API version).
- The controller runs as one replica with leader election. Describe this as
  design scope.
- Unverified live: whether the edge accepts a `127.0.0.1` answer for private
  hostnames, and long-streaming limits. Source:
  [`docs/operations/troubleshooting.md`](../../../../docs/operations/troubleshooting.md).
- Conformance: a local `dev` run under `conformanceMode`, which disables
  Cloudflare Tunnel, DNS, Access, and WARP; it validates Envoy behavior, not
  the edge path. Result numbers belong only on the conformance report page.
  Source:
  [`conformance/reports/v1.6.2/flareway/README.md`](../../../../conformance/reports/v1.6.2/flareway/README.md).

## Architecture (smallest accurate model)

- A `Gateway` references its `CloudflareTunnel` through
  `spec.infrastructure.parametersRef` (no annotations) and gets one
  data-plane Deployment whose pods run:
  - `cloudflared` — outbound QUIC/HTTP2 to Cloudflare's edge; no inbound
    ports or public IPs; transport only, forwarding each hostname to a
    loopback Envoy port.
  - Envoy — L7 routing streamed over xDS (Delta ADS).
  - CoreDNS sidecar (private listeners only) — resolves private hostnames to
    `127.0.0.1` so WARP traffic flows through Envoy.
- Public listeners get proxied CNAMEs to the tunnel hostname with an
  ownership comment; private listeners terminate TLS at Envoy and are reached
  over Cloudflare private network routes.
- `CloudflareTunnel` also has a Direct mode owning the full remote
  `cloudflared` config for non-Gateway services (TCP, SSH, RDP, bastion).
- Full explanation: [`docs/concepts/how-it-works.md`](../../../../docs/concepts/how-it-works.md).

## Resource families

Gateway and account (`GatewayClassConfig`, `CloudflareAccount`,
`CloudflareTunnel`), Access, private networking (`VirtualNetwork`,
`NetworkRoute`, `HostnameRoute`, `WARPConnector`), and account-wide settings.
The README does not list or count them; `docs/concepts/how-it-works.md` has
the table. Schema source of truth: `config/crd/bases/` and
[`docs/api-reference.md`](../../../../docs/api-reference.md).

## First safe action and install path

- Install only from the public OCI chart
  `oci://ghcr.io/isac322/charts/flareway`. Never document `./charts/flareway`,
  `charts/flareway/crds/`, a git checkout, `go run`, or Kustomize overlays
  as a user install path; contributor workflows stay in `CONTRIBUTING.md`.
- Safe first action, needing no cluster or credentials:

  ```sh
  helm template flareway oci://ghcr.io/isac322/charts/flareway \
    --namespace flareway-system \
    --set gatewayClass.create=true
  ```

  It renders the controller Deployment, RBAC, Services, NetworkPolicies,
  `GatewayClass/flareway`, and `GatewayClassConfig/default`;
  `--include-crds` adds the Flareway CRDs. Preview commands omit `--version`.
- Install and upgrade commands use `--version <chart-version>`; `helm show
  chart oci://ghcr.io/isac322/charts/flareway` prints the latest `version`.
  Do not hard-code a chart version.
- Real install prerequisites: Gateway API **v1.6.2 Standard** CRDs applied
  first (the chart does not install them), Helm 4.3 or a compatible Helm 3
  client, a Cloudflare account and scoped API token, a DNS zone for public
  listeners, WARP prerequisites for private listeners.
- Namespace is fixed `flareway-system`; `namespace.create` defaults `false`
  → use `--create-namespace`. `gatewayClass.create` defaults `false` →
  `--set gatewayClass.create=true` (prevents silently taking an existing
  GatewayClass).
- Never invite applying `config/samples/` files blindly: they contain
  placeholders (API token, account ID, hostnames, IdP/policy IDs) that must
  be replaced first.
- Source: [`docs/get-started/install.md`](../../../../docs/get-started/install.md).

## Documentation links (site tab order)

- Concepts:
  [`docs/concepts/how-it-works.md`](../../../../docs/concepts/how-it-works.md),
  [`docs/concepts/http-routing.md`](../../../../docs/concepts/http-routing.md),
  [`conformance/reports/v1.6.2/flareway/README.md`](../../../../conformance/reports/v1.6.2/flareway/README.md),
  [`docs/concepts/security-model.md`](../../../../docs/concepts/security-model.md),
  [`docs/concepts/ownership-and-adoption.md`](../../../../docs/concepts/ownership-and-adoption.md),
  [`docs/concepts/limits.md`](../../../../docs/concepts/limits.md)
- Get started:
  [`docs/get-started/install.md`](../../../../docs/get-started/install.md),
  [`docs/get-started/connect-cloudflare.md`](../../../../docs/get-started/connect-cloudflare.md),
  [`docs/get-started/expose-a-service.md`](../../../../docs/get-started/expose-a-service.md),
  [`docs/get-started/protect-with-access.md`](../../../../docs/get-started/protect-with-access.md),
  [`docs/get-started/private-services-over-warp.md`](../../../../docs/get-started/private-services-over-warp.md),
  [`docs/get-started/direct-tunnels.md`](../../../../docs/get-started/direct-tunnels.md)
- Operations:
  [`docs/operations/troubleshooting.md`](../../../../docs/operations/troubleshooting.md),
  [`docs/operations/upgrade.md`](../../../../docs/operations/upgrade.md),
  [`docs/operations/freshness-and-drift.md`](../../../../docs/operations/freshness-and-drift.md)
- Reference:
  [`docs/api-reference.md`](../../../../docs/api-reference.md),
  [`charts/flareway/README.md`](../../../../charts/flareway/README.md),
  [`docs/api/README.md`](../../../../docs/api/README.md),
  [`config/samples/`](../../../../config/samples/)
- Project:
  [`CONTRIBUTING.md`](../../../../CONTRIBUTING.md),
  [`SECURITY.md`](../../../../SECURITY.md),
  [`CODE_OF_CONDUCT.md`](../../../../CODE_OF_CONDUCT.md),
  design documents in Korean
  ([`docs/design/001-cloudflare-gateway-api-integration.md`](../../../../docs/design/001-cloudflare-gateway-api-integration.md))

## License and maintenance

Apache License 2.0, Copyright 2026 Byeonghoon Yoo —
[`LICENSE`](../../../../LICENSE). Contributor/help information comes only
from existing metadata and docs; no fabricated Slack/Discord/contact
channels.

## Claims not to make

- No "experimental", "beta", "not production", "production-grade",
  "battle-tested", HA, multi-replica, or adoption/user-count claims.
- No counts as selling points (CRD totals, conformance pass counts) outside
  the conformance report.
- No "Gateway API conformant", "certified", or edge-path conformance claims;
  say it passed the conformance suite in a local run and link the report.
- No "Envoy verifies every request" or "one outbound connection" (the
  connector defaults to two replicas).
- No competitor names, and no "only", "first", or "no other operator".
- No performance, latency, cost, or free-tier guarantees.
- No change narrative: describe current behavior only, never "now", "no
  longer", or "previously".
- No silent widening of supported mode boundaries (Gateway vs Direct).
