# Gateway API conformance reports

`standard-dev-default-report.yaml` records a successful local development run on September 13, 2026. GatewayHTTP Core passed 37/37 tests, the 30 tests for the claimed Extended features passed 30/30, and the suite recorded zero skips and zero failures.

The report's implementation version is `dev`. It is evidence for this checkout, not a release submission. The suite used `GatewayClassConfig.spec.conformanceMode: true` and verified Gateway API behavior through Envoy; it did not test Cloudflare Tunnel, DNS, Access, WARP, D-03 streaming, or D-11 private-hostname behavior.

## Reproduce

Run the portable workflow with Docker, Go, and `kubectl` installed:

```sh
make conformance
```

The script creates or reuses the `flareway-conf` kind cluster, installs Gateway API v1.6.2 and Flareway, builds the controller image, and applies the conformance `GatewayClass`.

On Linux, it starts cloud-provider-kind and verifies that it can assign a LoadBalancer address before running the suite from the host. On macOS, or when the provider probe fails, it switches the conformance Service to `ClusterIP` and runs the compiled test binary in a Kubernetes Job. The Job writes the report to a shared volume, and the script copies it to this directory.
The runner disables test parallelism because Flareway v1 deliberately uses one controller replica and one Gateway reconciliation worker. This serializes independent fixtures without skipping tests or weakening their assertions.

Useful overrides:

```sh
KIND_CLUSTER_NAME=my-cluster \
VERSION=dev \
REPORT_OUTPUT="$PWD/conformance/reports/v1.6.2/flareway/standard-dev-default-report.yaml" \
make conformance
```

The workflow does not invoke `sudo`. It pins kind, cloud-provider-kind, ko, kustomize, the kind node image, and Gateway API to the versions declared in the repository.
