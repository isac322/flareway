---
title: Architecture
description: How a Gateway becomes a Cloudflare Tunnel, how cloudflared and Envoy split transport and routing, and the two authorization layers that fail closed.
editUrl: https://github.com/isac322/flareway/edit/main/site/src/content/docs/docs/architecture/index.md
sidebar:
  order: 0
---

Flareway implements the Kubernetes Gateway API (`gateway.networking.k8s.io/v1`)
on top of Cloudflare's edge. This page describes the moving parts and the
security model that governs them.

## One Gateway, one tunnel, one data plane

Each `Gateway` maps to one `CloudflareTunnel` and one data-plane Deployment.
The pod runs `cloudflared` and Envoy, plus a CoreDNS sidecar when the Gateway
has private listeners:

- `cloudflared` opens outbound QUIC/HTTP2 connections to Cloudflare's edge.
  No inbound ports or public IPs are required.
- Envoy receives decrypted requests from `cloudflared` over loopback and
  applies the routing rules the controller streams to it over xDS (Delta ADS):
  path, header, query, and method matching, rewrites, and weighted backends.
- A CoreDNS sidecar is added for Gateways with private listeners. It resolves
  private hostnames to `127.0.0.1` so WARP private traffic also flows through
  Envoy.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="/assets/architecture/layers-dark.svg">
  <img src="/assets/architecture/layers-light.svg" alt="Four layers: Internet and WARP clients, the Cloudflare edge with edge TLS and private network routes, one outbound tunnel piercing a sealed cluster boundary while inbound is blocked, and the Kubernetes data-plane pod feeding Services and backend Pods">
</picture>

Both exposure modes ride that one outbound connection: public hostnames reach
it through the Cloudflare edge, and WARP devices reach it through a private
network route. Nothing listens for inbound traffic on the cluster side.

## Cluster topology

The same picture in Kubernetes-object terms: the node, the controller pod, and
the data-plane pod's containers.

<img src="/assets/architecture/topology.svg" alt="One Kubernetes node runs the single-replica Flareway controller pod and a data-plane pod containing cloudflared, Envoy, and a CoreDNS sidecar. Inbound traffic is blocked at the cluster wall; the only passage is one outbound tunnel that cloudflared opens to the Cloudflare edge, which forks to Internet users via a proxied CNAME and to WARP devices via a VirtualNetwork private route">

## Access policies on routes

When an `AccessApplication` targets a route, the controller configures the
matching Cloudflare Access application and policy, and configures Envoy's
`jwt_authn` filter to verify the `Cf-Access-Jwt-Assertion` token against
Cloudflare's JWKS endpoint. Routes without an Access attachment carry no JWT
filter.

## TLS for public and private listeners

For public listeners, Cloudflare owns edge TLS: Flareway creates proxied CNAME
records pointing to the tunnel hostname, marks ownership in the record
comment, and rejects a listener that references its own certificates.

Private listeners are the reverse: Envoy terminates TLS, so `certificateRefs`
is required and must name a Secret you supply (cert-manager or an internal CA;
Flareway does not issue certificates). WARP clients then reach the service
through Cloudflare's private network routes.

## Direct mode

`CloudflareTunnel` also supports a Direct mode that owns the complete remote
`cloudflared` configuration for non-Gateway services such as TCP, SSH, RDP,
and bastion origins.

## Security model

Two authorization layers both must allow an operation: Kubernetes RBAC for the
controller, and `CloudflareAccount.spec.grants` for which namespaces,
hostnames, zones, and exposures may use an account.

- Flareway fails closed on denial.
- Existing remote objects require explicit `AdoptById` adoption.
- Credentials stay in Secrets and out of status.
- A Gateway reports `Programmed` only after edge DNS, tunnel sessions, xDS
  configuration, and the Envoy data plane have all converged.

Details: [RBAC and Cloudflare API tokens](/docs/operations/rbac-token/).

## Design documents

The full model, including ownership, adoption, and fail-closed behavior, is
specified in the design documents:

- [Cloudflare Gateway API integration](https://github.com/isac322/flareway/blob/main/docs/design/001-cloudflare-gateway-api-integration.md) (Korean)
- [Tunnel status consistency](https://github.com/isac322/flareway/blob/main/docs/design/002-tunnel-status-consistency.md) (Korean)
