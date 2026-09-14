# Flareway API reference

Flareway serves `v1alpha1` resources in the `flareway.bhyoo.com` API group. The generated CRDs in [`config/crd/bases/`](../../config/crd/bases/) are the schema source of truth. The design document explains behavior, ownership, and security contracts without duplicating every OpenAPI field: [`docs/design/001-cloudflare-gateway-api-integration.md`](../design/001-cloudflare-gateway-api-integration.md).

## Resource groups

| Area | Resources |
|---|---|
| Gateway and account | `GatewayClassConfig`, `CloudflareAccount`, `CloudflareTunnel` |
| Access | `AccessApplication`, `AccessPolicy`, `AccessGroup`, `IdentityProvider`, `DevicePostureRule`, `ServiceToken` |
| Private network | `VirtualNetwork`, `NetworkRoute`, `HostnameRoute` |
| Account-wide settings | `DeviceProfile`, `DeviceSettings`, `ZeroTrustOrganization`, `ZeroTrustGatewayPolicy`, `ZeroTrustList` |

Gateway traffic uses the upstream `gateway.networking.k8s.io/v1` `GatewayClass`, `Gateway`, `HTTPRoute`, and `BackendTLSPolicy` resources.

## Inspect the installed schema

`kubectl explain` reads the schema installed in the cluster, so its output always matches the deployed CRD version.

```sh
kubectl explain gatewayclassconfig.spec --api-version=flareway.bhyoo.com/v1alpha1
kubectl explain cloudflareaccount.spec.grants --api-version=flareway.bhyoo.com/v1alpha1
kubectl explain cloudflaretunnel.spec --api-version=flareway.bhyoo.com/v1alpha1
kubectl explain accessapplication.spec --api-version=flareway.bhyoo.com/v1alpha1
kubectl explain accesspolicy.spec --api-version=flareway.bhyoo.com/v1alpha1
kubectl explain accessgroup.spec --api-version=flareway.bhyoo.com/v1alpha1
kubectl explain identityprovider.spec --api-version=flareway.bhyoo.com/v1alpha1
kubectl explain deviceposturerule.spec --api-version=flareway.bhyoo.com/v1alpha1
kubectl explain servicetoken.spec --api-version=flareway.bhyoo.com/v1alpha1
kubectl explain virtualnetwork.spec --api-version=flareway.bhyoo.com/v1alpha1
kubectl explain networkroute.spec --api-version=flareway.bhyoo.com/v1alpha1
kubectl explain hostnameroute.spec --api-version=flareway.bhyoo.com/v1alpha1
kubectl explain deviceprofile.spec --api-version=flareway.bhyoo.com/v1alpha1
kubectl explain devicesettings.spec --api-version=flareway.bhyoo.com/v1alpha1
kubectl explain zerotrustorganization.spec --api-version=flareway.bhyoo.com/v1alpha1
kubectl explain zerotrustgatewaypolicy.spec --api-version=flareway.bhyoo.com/v1alpha1
kubectl explain zerotrustlist.spec --api-version=flareway.bhyoo.com/v1alpha1
```

Add `--recursive` to inspect nested fields. Use `kubectl explain httproute.spec.rules --api-version=gateway.networking.k8s.io/v1` for the upstream routing API.

## Examples

Individual resource examples and complete workload mappings live in [`config/samples/`](../../config/samples/). The complete mappings are:

- [`workload_cc_lb.yaml`](../../config/samples/workload_cc_lb.yaml)
- [`workload_codex_lb.yaml`](../../config/samples/workload_codex_lb.yaml)
- [`workload_cliproxyapi.yaml`](../../config/samples/workload_cliproxyapi.yaml)

All IDs, tokens, hostnames, and account details in those files are placeholders.
