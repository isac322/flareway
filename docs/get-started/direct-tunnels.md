# Direct tunnels for TCP, SSH, and RDP origins

A `CloudflareTunnel` in Direct mode owns the whole `cloudflared` configuration for origins outside a Gateway, such as TCP, SSH, RDP, and bastion hosts.

## When to use Direct mode

Use a Gateway when the origin speaks HTTP and you want `HTTPRoute` rules, Envoy routing, and `AccessApplication` attachments. Use Direct mode when the origin is a database, an SSH or RDP host, an SMB share, a Unix socket, or a bastion, or when you want to write `cloudflared` ingress rules yourself. Gateways serve `HTTPRoute` only; [Limits](../concepts/limits.md#gateway-api-scope) lists the Gateway API scope.

A Direct tunnel has no Gateway data plane. Flareway creates the tunnel, writes its remote configuration, manages its DNS records, and stores the connector token in a Secret it owns. You run `cloudflared` with that token wherever it can reach the origins.

## Before you start

Complete [Install](install.md) and [Connect a Cloudflare account](connect-cloudflare.md). The example uses the `demo` namespace from [Reach private Services over Cloudflare WARP](private-services-over-warp.md). If you skipped that guide, create `demo` first, or change the manifest's namespace to one you have.

The grant that selects the tunnel's namespace must allow four things:

- `platformObjects: Allowed`, because Flareway treats a Direct tunnel as a platform object.
- `Public` in `exposures`. Every named Direct ingress rule is a public edge hostname, even when its origin speaks TCP, SSH, or RDP.
- every ingress hostname in `hostnames`, and its zone in `zones`. The zone must also be one the account verified.
- every hostname whose rule does not require Access at the origin in `unprotectedHostnames`. A rule requires it when its effective `originRequest.access` sets `required: true`; a rule-level `originRequest` replaces the top-level one for this check.

For the example below, change the `demo` grant from the WARP guide so these fields read:

```yaml
    hostnames:
    - admin.internal.example
    - "*.direct.example.com"
    zones:
    - example.com
    exposures:
    - Private
    - Public
    unprotectedHostnames:
    - "*.direct.example.com"
```

Keep its other fields, including `platformObjects: Allowed`, and apply `cloudflareaccount.yaml` again. The wildcard also covers `http.direct.example.com`, whose rule requires Access; Flareway checks `unprotectedHostnames` only for rules that do not. If you skipped the WARP guide, add a grant for your namespace with these fields plus `platformObjects: Allowed`.

## Configure `configuration.mode: Direct`

Set `spec.configuration.mode: Direct` and put the rules under `spec.configuration.direct`:

- `direct.ingress` is an ordered list of up to 200 rules. Each rule has an optional `hostname` and `path` and exactly one service.
- The services are `http`, `https`, `tcp`, `ssh`, `rdp`, and `smb` with an `address`; `unix` and `unixTLS` with a socket `path`; and the built-ins `helloWorld`, `httpStatus`, and `bastion`.
- The last rule must be a catch-all with no hostname and no path.
- `originRequest` can be set at the top level of `direct` or on a rule. `originRequest.access` (`audTags`, `teamName`, `required`) is valid only for HTTP, HTTPS, Unix, and Unix TLS origins. You supply the AUD tags and team name yourself; `AccessApplication` attaches only to Gateways and routes.
- `originRequest.ipRules` requires the `bastion` service or `proxyType: SOCKS5`.
- `direct.warpRouting` sets `enabled`, `connectTimeout`, `tcpKeepAlive`, and `maxActiveFlows`.

The API server rejects a manifest that breaks these rules.

With `originRequest.access`, `cloudflared` verifies the Access JWT at the origin, the same check it runs for protected Gateway hostnames; [Security model](../concepts/security-model.md#access-enforcement) describes it.

## Full example

[`flareway_v1alpha1_cloudflaretunnel_direct.yaml`](../../config/samples/flareway_v1alpha1_cloudflaretunnel_direct.yaml) uses every service type and every `originRequest` field:

```yaml
apiVersion: flareway.bhyoo.com/v1alpha1
kind: CloudflareTunnel
metadata:
  name: direct-services
  namespace: demo
spec:
  accountRef:
    name: example-account
  tunnel:
    name: flareway-example-direct-services
  configuration:
    # Direct mode is the sole writer of the complete remote cloudflared configuration.
    # Do not attach this tunnel to a Gateway or add Gateway-mode listeners.
    mode: Direct
    direct:
      ingress:
      - hostname: http.direct.example.com
        path: ^/api(/|$)
        service:
          http:
            address: web.demo.svc.cluster.local:8080
        # This rule sets every originRequest field. SOCKS5 makes ipRules applicable.
        originRequest:
          access:
            audTags:
            - direct-services-aud
            teamName: example-team
            required: true
          caPool: /etc/cloudflared/ca.pem
          connectTimeout: 30
          disableChunkedEncoding: true
          http2Origin: true
          httpHostHeader: origin.example.com
          keepAliveConnections: 100
          keepAliveTimeout: 90
          matchSNIToHost: true
          noHappyEyeballs: true
          noTLSVerify: false
          originServerName: tls.example.com
          proxyType: SOCKS5
          tcpKeepAlive: 30
          tlsTimeout: 10
          ipRules:
          - prefix: 10.0.0.0/8
            ports:
            - 80
            - 443
            allow: true
          - prefix: 0.0.0.0/0
            allow: false
      - hostname: https.direct.example.com
        service:
          https:
            address: web.demo.svc.cluster.local:8443
      - hostname: tcp.direct.example.com
        service:
          tcp:
            address: database.demo.svc.cluster.local:5432
      - hostname: ssh.direct.example.com
        service:
          ssh:
            address: bastion.demo.svc.cluster.local:22
      - hostname: rdp.direct.example.com
        service:
          rdp:
            address: desktop.demo.svc.cluster.local:3389
      - hostname: smb.direct.example.com
        service:
          smb:
            address: files.demo.svc.cluster.local:445
      - hostname: unix.direct.example.com
        service:
          unix:
            path: /var/run/origin.sock
      - hostname: unix-tls.direct.example.com
        service:
          unixTLS:
            path: /var/run/origin-tls.sock
      - hostname: hello.direct.example.com
        service:
          helloWorld: {}
      - hostname: bastion.direct.example.com
        service:
          bastion: {}
        originRequest:
          proxyType: SOCKS5
          ipRules:
          - prefix: 10.20.0.0/16
            ports:
            - 22
            allow: true
      # Direct ingress must end with one hostname-free, path-free catch-all rule.
      - service:
          httpStatus:
            code: 404
      warpRouting:
        enabled: true
        connectTimeout: 30
        tcpKeepAlive: 30
        maxActiveFlows: 10000
  managementPolicy: Managed
  adoption:
    mode: None
  deletionPolicy: Delete
  dns:
    mode: Managed
    recordComment: direct tunnel sample
    proxied: true
    ttl: 1
    settings:
      ipv4Only: true
      ipv6Only: false
```

In this sample only `http.direct.example.com` requires Access at the origin, so every other hostname must be listed in the grant's `unprotectedHostnames`.

Apply it, then find the connector token Secret:

```sh
kubectl apply -f direct-services.yaml
kubectl -n demo get cloudflaretunnel direct-services \
  -o jsonpath='{.status.connectorTokenSecretRef.name}'
```

The Secret is named `flareway-tunnel-direct-services`, and its `token` key holds the connector token. Run `cloudflared tunnel run --token <token>` where the origins are reachable; the sample's addresses are cluster Service names, so that means inside the cluster.

Check the tunnel's conditions:

```sh
kubectl -n demo get cloudflaretunnel direct-services \
  -o jsonpath='{range .status.conditions[*]}{.type}={.status} {.reason}{"\n"}{end}'
```

`Accepted=True` means the grant allows every binding. `ConfigApplied=True` with reason `Applied` means Flareway wrote the configuration to Cloudflare, and `DNSReady=True` means the records exist. If `Accepted=False`, the reason and message name the gate that failed, such as a hostname missing from `unprotectedHostnames`.

## One writer per tunnel

Exactly one writer owns a tunnel's configuration: the Gateway in Gateway mode, or the `CloudflareTunnel` itself in Direct mode. The API server rejects a Direct tunnel that also sets the Gateway-mode fields `connector`, `proxy`, `privateDNS`, `originRequest`, or `listeners`. If admission reports this, remove those fields or set the mode back to `Gateway`.

Do not attach a Direct tunnel to a Gateway. To move a tunnel from Gateway mode to Direct mode, set the mode and the `direct` block together; do not copy the generated Gateway ingress into it while a Gateway still references the tunnel. Flareway first drains the connector Pods of the Gateway that owned the tunnel and reports `Accepted=False` with reason `WaitingForDrain` until they are gone. Only then does Direct mode write the configuration.

## DNS for Direct tunnels

`dns` works the same way in both modes. With `mode: Managed`, Flareway creates a proxied CNAME record for each Direct hostname and records its ownership in the record comment; it never overwrites a record another owner holds. With `mode: External`, it writes no records, and another tool such as external-dns owns them.

- A proxied record requires automatic TTL (`ttl: 1`).
- `settings.ipv4Only` and `settings.ipv6Only` are mutually exclusive, and either one requires `proxied: true`.

## Optional management token

Set `spec.managementToken.resources: [Logs]` to request a short-lived token for the tunnel's logs. Flareway writes the issued token only to a Secret the tunnel owns and names it in `status.managementTokenSecretRef`. The chart exposes no global setting for Direct mode or management tokens; both are set per `CloudflareTunnel`.

The [API reference](../api-reference.md) documents every Direct field.

Next: [Troubleshooting](../operations/troubleshooting.md).
