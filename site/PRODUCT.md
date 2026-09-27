# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

Astro + Starlight, built and run 100% with Bun (no Node/npm toolchain in scripts, lockfile, or CI). Static output deployed to GitHub Pages at https://flareway.bhyoo.com. Lives in `site/` of the flareway repository; documentation pages are generated from the repository's own Markdown (`docs/`, conformance report) at build time rather than duplicated.

## Users

Platform and Kubernetes engineers (homelab operators through small platform teams) who already use, or are evaluating, Cloudflare Tunnel / Zero Trust and want to expose cluster services without inbound ports or public IPs. They arrive from search, GitHub, or a Gateway API implementations list, usually comparing against running `cloudflared` by hand or other tunnel operators, and they decide within a minute whether the project is serious enough to read the install guide.

## Product Purpose

Flareway is a Kubernetes operator that implements the Gateway API (`gateway.networking.k8s.io/v1`) on top of Cloudflare's edge: a `Gateway` becomes a Cloudflare Tunnel, `HTTPRoute` rules become L7 routing executed by an in-pod Envoy data plane, and Cloudflare Access policies attach to routes via GEP-713 policy attachment. It also manages WARP private networking and Zero Trust account resources as CRDs (22 CRDs in `flareway.bhyoo.com/v1alpha1`). Success for the site: a visitor understands the mechanism in one viewport, trusts the engineering rigor, and follows through to the install guide or the GitHub repository.

## Positioning

`cloudflared` alone matches only hostnames and simple paths. Flareway pairs `cloudflared` (outbound-only transport) with an in-pod Envoy fed over xDS, so standard `HTTPRoute` method/header/query matches, rewrites, and weighted splits work behind a Cloudflare Tunnel, and Access (Zero Trust) policies live next to the routes they protect. One outbound connection; nothing listens for inbound traffic on the cluster side.

## Operating Context

Evaluated through: `helm template` rendering (no cluster or credentials needed), `config/samples/` manifests, the Helm chart (`charts/flareway`, OCI chart on release), `kubectl explain`, the Gateway API conformance report, and the design document. Installed with Gateway API v1.6.2 Standard CRDs, a Cloudflare account with a scoped API token, a DNS zone for public listeners, and WARP prerequisites for private listeners.

## Capabilities and Constraints

- Gateway ↔ CloudflareTunnel ↔ data-plane Deployment, 1:1:1. Pod runs `cloudflared` + Envoy (+ CoreDNS sidecar for private listeners).
- Public listeners: Cloudflare owns edge TLS; proxied CNAMEs with ownership marked in record comments. Private listeners: Envoy terminates TLS with user-supplied certificates; WARP clients reach via private network routes.
- Access: `AccessApplication` targets routes; Envoy `jwt_authn` verifies `Cf-Access-Jwt-Assertion` against Cloudflare JWKS.
- `CloudflareTunnel` Direct mode for non-Gateway TCP/SSH/RDP/bastion origins.
- Security: two authorization layers (Kubernetes RBAC + `CloudflareAccount.spec.grants`), fail-closed, explicit `AdoptById` adoption, credentials only in Secrets, `Programmed` only after DNS, tunnel, xDS, and Envoy converge.
- Status: experimental, `v1alpha1`, single-replica controller, not yet production ingress. This must stay visible; never implied otherwise.
- Conformance: local `dev` run on kind in `conformanceMode` (Cloudflare paths disabled): GatewayHTTP Core 37/37, claimed Extended 30/30, 13 unsupported features listed.

## Brand Commitments

- Name is lowercase `flareway` in the wordmark; "Flareway" in prose.
- Logo (orange cloud with an open doorway, `assets/cloud-gateway/d2/logo-t3.svg`) and the navy serif lowercase wordmark are fixed (`assets/social-card.svg`). Everything else (extended palette, type system, motion) may expand around them.
- English only.
- Not affiliated with Cloudflare or the Kubernetes project; do not combine the Kubernetes Gateway API and Cloudflare logos.

## Evidence on Hand

Architecture diagrams (`assets/architecture/layers-{light,dark}.svg`, `topology.svg`), social card, README, docs (`docs/operations/*`, `docs/api-reference.md`, `docs/api/README.md`, `docs/design/*`), conformance report (`conformance/reports/v1.6.2/flareway/README.md`), sample manifests. No users, testimonials, logos of adopters, benchmarks, pricing, or download counts exist; never fabricate them.

## Product Principles

1. Honesty over hype: every claim traceable to the repo; experimental status stated plainly.
2. Show the mechanism: outbound-only tunnel + Envoy routing is the story.
3. Kubernetes-native first: standard Gateway API objects, zero annotations.
4. Fail closed: security posture is a feature, not fine print.

## Accessibility & Inclusion

WCAG 2.2 AA; respect `prefers-reduced-motion` and `prefers-color-scheme`; full keyboard navigation.
