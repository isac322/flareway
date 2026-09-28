# Ownership, adoption, and teardown

Flareway never takes over an existing tunnel, DNS record, or Access application by name. It adopts by ID with expected attributes and tears down in order.

## Lifecycle fields

Resources that represent a distinct Cloudflare object, addressed by ID, use three lifecycle fields:

| Field | Values | Meaning |
|---|---|---|
| `managementPolicy` | `Managed`, `ObserveOnly` | `Managed` permits remote writes. `ObserveOnly` requires an `externalRef`, never claims an object by name, and makes no remote changes; it only reports what it observes in status. |
| `adoption.mode` | `None`, `AdoptById` | `AdoptById` requires an `externalRef` and the `adoption.expect` attributes the remote object must match. A matching name is never enough. |
| `deletionPolicy` | `Delete`, `Orphan` | `Delete` removes the remote object when the Kubernetes object is deleted. `Orphan` leaves it in Cloudflare. |

Defaults and the exact reference path differ by kind; the [API reference](../api-reference.md) lists them. A `CloudflareTunnel` takes its reference at `spec.tunnel.externalRef`. The account singletons `DeviceSettings` and `ZeroTrustOrganization` have no `externalRef` or adoption block and default to `ObserveOnly`, and `ZeroTrustOrganization` accepts only `deletionPolicy: Orphan`.

## The ownership ledger

Flareway records ownership on the Cloudflare side as well as in Kubernetes:

- tags, where Cloudflare supports tags;
- deterministic comments on DNS records and private-network resources;
- a Flareway name prefix, where Cloudflare offers only a name;
- the remote ID in the object's status.

A foreign or ambiguous marker produces `Accepted=False` with reason `Conflict`, and Flareway leaves the remote object untouched. A managed DNS record, for example, is never overwritten when its comment names another owner.

When a `Conflict` persists, compare:

- the Kubernetes object's UID and the remote ID in its status;
- the remote tag, comment, or Flareway name prefix;
- `adoption.expect.name` or `adoption.expect.domain`;
- other writers, such as Terraform, GitOps tooling, or another controller.

Identify the current owner before you change `managementPolicy` or adoption settings.

## Bringing existing objects under Flareway

Adoption is explicit. For an ID-addressed resource it takes four steps:

1. Set `managementPolicy: ObserveOnly`, `externalRef`, and `deletionPolicy: Orphan`. Flareway reads the object and changes nothing.
2. Resolve the drift that conditions and the bounded observed status report.
3. Set `managementPolicy: Managed`, `adoption.mode: AdoptById`, and `adoption.expect` values that identify the intended remote object. Flareway compares the remote ID and these expectations before it sets `status.ownershipVerified`.
4. Change `deletionPolicy` only after ownership is verified.

Step 1 looks like this sample from [`config/samples/flareway_v1alpha1_accessgroup_observeonly.yaml`](../../config/samples/flareway_v1alpha1_accessgroup_observeonly.yaml):

```yaml
apiVersion: flareway.bhyoo.com/v1alpha1
kind: AccessGroup
metadata:
  name: developers
  namespace: default
spec:
  accountRef:
    name: example-account
  name: developers
  include:
  - emailDomain:
      domain: example.com
  managementPolicy: ObserveOnly
  externalRef:
    groupId: "00000000-0000-0000-0000-000000000002"
  deletionPolicy: Orphan
```

Step 3 adds the adoption block, as in [`config/samples/flareway_v1alpha1_accessstandaloneapplication.yaml`](../../config/samples/flareway_v1alpha1_accessstandaloneapplication.yaml):

```yaml
  externalRef:
    applicationId: replace-with-existing-warp-enrollment-application-id
  adoption:
    mode: AdoptById
    expect:
      name: WARP enrollment
  managementPolicy: Managed
  deletionPolicy: Orphan
```

Adoption never switches an application's immutable `type`, infers a tunnel mode, replaces a typed route kind, or recreates a missing one-time Secret. Each of those can change IDs, AUD tags, or credentials, so each needs a deliberate replacement plan.

### Bypass children

When a protected Access application contains a public path carve-out, Flareway creates a more specific child Access application for that path. An existing child is never adopted by hostname or name alone. Declare its normalized `hostname` and `path` under `spec.bypass.children[]`, set `externalRef.applicationId`, and use `adoption.mode: AdoptById` with expected attributes. An `ObserveOnly` parent needs an `externalRef` for every declared child.

A child's ownership conflict appears on the parent: the parent `AccessApplication` reports `Programmed=False` with reason `Pending` and a message that begins `Remote bypass application reconciliation failed:`. Compare the remote application ID, the normalized path, the expected name or domain, and the Flareway ownership tags. Do not delete the protected parent to clear a child conflict: that widens the outage and can change the parent's AUD tag.

## Coexisting with Terraform and GitOps

Keep objects that another tool owns, such as shared Access policies and identity providers managed by Terraform, as `managementPolicy: ObserveOnly` with `deletionPolicy: Orphan`. Flareway reads them, reports their state, and lets your applications reference them without writing to them.

## Gateway ownership of a tunnel

In Gateway mode, one `Gateway` owns a `CloudflareTunnel`. The tunnel records its owner in `status.gatewayRef` and `status.gatewayUid`, so ownership is bound to that Gateway's UID. A Gateway recreated with the same name does not inherit it, and a second Gateway that references the tunnel is not accepted while the recorded owner exists.

To hand a tunnel to another Gateway, remove or delete the current owner, then wait for its connector Deployment and Pods to drain. Flareway admits the successor only after the drain. Do not force a handoff by changing names or timestamps.

If the tunnel is deleted in Cloudflare, Flareway sets `status.deletedAt`. It keeps the ownership record for cleanup but stops sending xDS updates, scaling up connectors, publishing addresses, and writing private routes or tunnel configuration.

[Direct tunnels](../get-started/direct-tunnels.md) covers the other mode, in which a `CloudflareTunnel` owns its whole `cloudflared` configuration without a Gateway.

## Ordered teardown

A managed tunnel is torn down in this order:

1. Public ingress returns `403`, and private virtual hosts deny all requests.
2. Managed DNS records are removed.
3. Connector Pods drain and stop.
4. Access applications are marked target-not-found and deleted only when their own `deletionPolicy` permits it.
5. Private routes release the tunnel.
6. The managed tunnel is deleted last.

If a step fails, the finalizer stays and the object reports `CleanupBlocked=True`. Restore the missing Cloudflare permission or remove the blocking reference, such as a remaining `NetworkRoute` or `HostnameRoute`, and reconciliation resumes. Do not strip a finalizer unless you accept leaked remote objects or exposed traffic.

An `AccessApplication` that never reached a Cloudflare write skips remote cleanup when you delete it. Once Flareway has attempted a write, deletion needs the namespace grant. If the grant was removed, the application reports `CleanupBlocked=True` with reason `RemoteError` and a message describing the authorization failure, plus `Programmed=False` with reason `CleanupBlocked`, until the grant is restored.

To uninstall Flareway, delete your application resources first, wait for their teardown to finish, and run `helm uninstall` last. Uninstalling the controller while finalizers are pending leaves cleanup unfinished. Flareway CRDs remain after `helm uninstall`, following Helm's CRD lifecycle.

## Controller groups are an ownership boundary

The chart runs controllers in groups (`controllers.gateway`, `controllers.access`, `controllers.privateNetwork`, `controllers.device`, `controllers.organization`), all enabled by default. Disable a group only when another system owns every object in that area. Before you disable one:

1. Set the affected objects to `managementPolicy: ObserveOnly`, or finish deleting them while the controller still runs.
2. Wait for status to show the observed or deleted state.
3. Confirm no finalizer depends on that controller group.
4. Disable the group in the Helm values.

Re-enable the group before you switch an object back to `Managed`.

Never run two Flareway installations that manage the same Cloudflare object. Ownership markers and `AdoptById` stop a takeover by name, but two writers on one object are not a supported configuration.

[Install Flareway](../get-started/install.md) lists the controllers in each group, and the [security model](security-model.md) covers the authorization checks that run before any of this.
