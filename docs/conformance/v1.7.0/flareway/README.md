# Gateway API conformance report (v1.7.0)

A local development run on November 8, 2026 passed GatewayHTTP Core 40/40 and the claimed Extended tests 42/42, with zero skips and zero failures.

## Results

[`standard-dev-default-report.yaml`](standard-dev-default-report.yaml) is the report the Gateway API v1.7.0 conformance suite wrote for that run, on the standard channel in default mode:

| Profile | Passed | Failed | Skipped |
|---|---|---|---|
| GatewayHTTP Core | 40 | 0 | 0 |
| GatewayHTTP Extended (claimed features) | 42 | 0 | 0 |

## What the run covered

The report's implementation version is `dev`, and the report has not been submitted to the Gateway API project. The run used `GatewayClassConfig.spec.conformanceMode: true`, in which Flareway performs no Cloudflare account operations and the suite reaches Envoy directly, so it validated Gateway API behavior through Envoy. The run includes the six provisional tests recorded in `succeededProvisionalTests`.

The run did not exercise Cloudflare Tunnel, DNS, Access, or WARP. It also did not test long-lived streams through Cloudflare's edge, or whether the edge accepts the `127.0.0.1` answer Flareway gives for private hostnames.

## Supported and unsupported features

The [report YAML](standard-dev-default-report.yaml) lists 32 supported and 11 unsupported Extended features by name, and [HTTP routing](../../../concepts/http-routing.md) explains each one, including what Flareway does with unsupported configuration.

## Serialized run

The runner disables test parallelism because Flareway deliberately runs one controller replica and one Gateway reconcile worker. This serializes independent fixtures without skipping tests or weakening their assertions.

## Reproduce

To run the suite yourself, follow [Gateway API conformance run](../../../CONTRIBUTING.md#gateway-api-conformance-run) in the contributing guide.
