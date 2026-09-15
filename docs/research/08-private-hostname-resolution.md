# Research Report: WARP Private Hostname Exposure & Origin Resolution in Cloudflare Tunnel

---

## Summary

When exposing private hostnames (e.g. `admin.internal.example`) to WARP clients via Cloudflare Tunnel, **`cloudflared` does not perform application-level DNS resolution at connection time**. Instead, Cloudflare Zero Trust splits private hostname routing into two distinct phases:

1. **Synthetic Resolution at Gateway Edge:** When a WARP client queries DNS for `admin.internal.example`, Cloudflare Gateway assigns a temporary "initial resolved IP" (drawn by default from `172.64.128.0/20`). Concurrently, Gateway queries `cloudflared` over the tunnel using a dedicated virtual DNS origin (`2606:4700:0cf1:2000::1:53`) to obtain the "real" origin IP.
2. **L4 Flow Forwarding to an Explicit IP:** When the WARP client initiates TCP/UDP traffic to the synthetic IP, Gateway rewrites the packet destination to the real IP resolved in Phase 1 and transmits a `ConnectRequest` / `TCPRequest` down the tunnel to `cloudflared`. `cloudflared` expects a concrete `IP:port` (`netip.AddrPort`) and dials it directly via Go's `net.Dialer.DialContext`.

### Crucial Findings for Flareway
- **`pod.spec.hostAliases` does NOT work:** `cloudflared` never invokes local libc `getaddrinfo` or `net.LookupIP` on incoming proxy flows. Furthermore, `cloudflared`'s Virtual DNS Service dynamically discovers the cluster's upstream nameserver from `/etc/resolv.conf` (e.g., `kube-dns` at `10.96.0.10:53`) and proxies raw DNS queries there. Kube-dns has no visibility into the pod's `/etc/hosts`. Therefore, Gateway receives `NXDOMAIN`.
- **`TUNNEL_DNS_RESOLVER_ADDRS` is the native hook:** `cloudflared` provides `--dns-resolver-addrs` (`TUNNEL_DNS_RESOLVER_ADDRS`). Pointing this to `127.0.0.1:53` instructs `cloudflared` to bypass `/etc/resolv.conf` and forward all Gateway virtual DNS queries to a pod-local DNS sidecar (CoreDNS or dnsmasq).
- **Loopback Dialing is Unrestricted:** In `cloudflared`, `WarpRoutingConfig` does not enforce any IP allowlists, bogon blocks, or loopback filters. It will dial `127.0.0.1:<port>` over the pod's shared network namespace without restriction.
- **TLS & Access Header Injection:** For private HTTP apps, Gateway operates at L4 unless **Gateway TLS Decryption** is enabled. Without TLS decryption, TLS is end-to-end between the client and Envoy; Cloudflare **cannot** inject `Cf-Access-Jwt-Assertion` or manage browser cookies. With TLS decryption enabled, Gateway terminates TLS, injects identity headers, and re-encrypts to Envoy.

---

## How cloudflared resolves/dials private-hostname flows (with source citations)

### 1. Ingress Proxy Execution Path
In `cloudflared` master (`f11dea9cb7079e90a982c1a2d5548ab40847fdcf`, Release 2026.9.1):
- Incoming private network TCP streams are dispatched by QUIC/HTTP2 connection managers (`connection/quic_connection.go:252` and `connection/http2.go:145`) into `Proxy.ProxyTCP`:
  ```go
  // proxy/proxy.go:147-178
  func (p *Proxy) ProxyTCP(ctx context.Context, conn connection.ReadWriteAcker, req *connection.TCPRequest) error {
      ...
      // Parse the destination into a netip.AddrPort
      dest, err := netip.ParseAddrPort(req.Dest)
      if err != nil {
          logRequestError(&logger, err)
          return err
      }

      if err := p.proxyTCPStream(tracedCtx, conn, dest, p.originDialer, &logger); err != nil { ... }
      return nil
  }
  ```
- **The edge sends an IP:port, never a hostname:** `req.Dest` is strictly parsed via `netip.ParseAddrPort(req.Dest)`. If the edge sent `admin.internal.example:80`, `ParseAddrPort` would immediately fail with an error.
- Dialing takes place in `ingress/origin_dialer.go:131`:
  ```go
  // ingress/origin_dialer.go:131-139
  func (d *Dialer) DialTCP(ctx context.Context, dest netip.AddrPort) (net.Conn, error) {
      conn, err := d.Dialer.DialContext(ctx, "tcp", dest.String())
      if err != nil {
          return nil, fmt.Errorf("unable to dial tcp to origin %s: %w", dest, err)
      }
      return conn, nil
  }
  ```

### 2. The Virtual DNS Origin Service
Because `ProxyTCP` requires an IP, Cloudflare Gateway must resolve the private hostname to an origin IP beforehand.
- In `cmd/cloudflared/tunnel/configuration.go:215-224`, `cloudflared` initializes a reserved virtual service:
  ```go
  originDialerService.AddReservedService(dnsService, []netip.AddrPort{origins.VirtualDNSServiceAddr})
  ```
- `VirtualDNSServiceAddr` is defined in `ingress/origins/dns.go:39`:
  ```go
  VirtualDNSServiceAddr = netip.AddrPortFrom(netip.MustParseAddr("2606:4700:0cf1:2000:0000:0000:0000:0001"), 53)
  ```
- When Gateway resolves a private hostname, it transmits a standard DNS query packet across the tunnel to `2606:4700:0cf1:2000::1:53`.
- `DNSResolverService.DialTCP` / `DialUDP` (`ingress/origins/dns.go:73-86`) intercepts this address:
  ```go
  func (s *DNSResolverService) DialTCP(ctx context.Context, _ netip.AddrPort) (net.Conn, error) {
      s.metrics.IncrementDNSTCPRequests()
      dest := s.getAddress()
      // The dialer ignores the provided address because the request will instead go to the local DNS resolver.
      return s.dialer.DialTCP(ctx, dest)
  }
  ```
- **How `getAddress()` learns the nameserver:**
  `StartRefreshLoop` (`ingress/origins/dns.go:88-149`) runs every 5 minutes and executes `s.update()`. `update()` resolves `defaultLookupHost = "region1.v2.argotunnel.com"` using Go's `net.Resolver{PreferGo: true}` with a custom dialer `peekDial`.
  `peekDial` intercepts Go's pure-Go resolver reading `/etc/resolv.conf`, captures the remote nameserver IP (e.g. `10.96.0.10:53`), and stores it in `s.addresses`.
- **The CLI / Env Override:**
  In `cmd/cloudflared/tunnel/configuration.go:214-222` and `cmd/cloudflared/flags/flags.go:168`:
  Flag: `--dns-resolver-addrs`
  Env: `TUNNEL_DNS_RESOLVER_ADDRS`
  When set, `origins.NewStaticDNSResolverService` is used. This disables the dynamic `peekDial` refresh loop and statically forces `cloudflared` to proxy all Virtual DNS queries to the specified address(es) (e.g., `127.0.0.1:53`).

---

## Hostname Route API Schema

**Endpoint:** `POST /accounts/{account_id}/zerotrust/routes/hostname`

### Request Body
```json
{
  "hostname": "admin.internal.example",
  "tunnel_id": "31b25026-6b2a-4a62-870a-73d8ab60ec87",
  "comment": "Managed by Flareway"
}
```
- `hostname` (string, required): FQDN. Up to 255 characters. Single wildcard (`*`) allowed for a full label (e.g. `*.internal.local`).
- `tunnel_id` (string/UUID, required): The target tunnel ID.
- `comment` (string, optional): Descriptive comment.
- **Note on API fields:** The API contains **no** `origin`, `resolver`, or `ip` override fields.

### Response Body (`tunnel_hostname_route_response_single`)
```json
{
  "success": true,
  "errors": [],
  "messages": [],
  "result": {
    "id": "f8a12e34-5678-90ab-cdef-1234567890ab",
    "hostname": "admin.internal.example",
    "tunnel_id": "31b25026-6b2a-4a62-870a-73d8ab60ec87",
    "tunnel_name": "flareway-gateway-tunnel",
    "comment": "Managed by Flareway",
    "created_at": "2026-09-13T00:00:00Z",
    "deleted_at": null,
    "tun_type": "cfd_tunnel"
  }
}
```

### Documentation Constraints
- **Wildcard rules:** A single wildcard label is supported (e.g., `*.internal.local`). Partial wildcards (`*-dev.internal`), mid-string wildcards (`foo.*.internal`), and multi-level wildcards (`*.*.internal`) are **rejected**.
- **Wildcard normalization:** Leading `*` is trimmed (`*.internal.local` is stored as `internal.local`), matching immediate subdomains (`app.internal.local`, but not `deep.sub.internal.local`).
- **Initial resolved IP:** Gateway assigns a synthetic IP from `172.64.128.0/20` (IPv4) or `2606:4700:0cf1:4000::/64` (IPv6).

---

## Option 1: hostAliases

### Description
Configuring Kubernetes `pod.spec.hostAliases` on the `cloudflared` pod:
```yaml
hostAliases:
  - ip: "127.0.0.1"
    hostnames:
      - "admin.internal.example"
```

### Evaluation
1. **Does it work at all?** **NO.** `cloudflared` does not query local host resolver files when processing WARP routing requests. It forwards the raw DNS request over port 53 to the nameserver specified in `/etc/resolv.conf` (`kube-dns` / cluster CoreDNS). Kube-dns cannot read `/etc/hosts` of an arbitrary pod and returns `NXDOMAIN`.
2. **Loopback reachability:** N/A (resolution fails before dialing).
3. **Wildcard support:** Kubernetes `hostAliases` does not support wildcard entries.
4. **Platform prerequisites:** None, but inherently static.
5. **Limitations:**
   - Requires `hostNetwork: false`.
   - Immutable in `PodSpec`: any change to private hostnames requires terminating and recreating the pod.

---

## Option 2: pod-local DNS sidecar

### Description
Deploy a lightweight DNS sidecar (CoreDNS or dnsmasq) inside the same pod as `cloudflared` and `envoy`, listening on `127.0.0.1:53`. Run `cloudflared` with:
```yaml
env:
  - name: TUNNEL_DNS_RESOLVER_ADDRS
    value: "127.0.0.1:53"
```
The CoreDNS sidecar uses a minimal Corefile:
```corefile
.:53 {
    hosts {
        127.0.0.1 admin.internal.example
        127.0.0.1 *.internal.example
        fallthrough
    }
    forward . /etc/resolv.conf
    reload 5s
}
```

### Evaluation
1. **Does it work at all?** **YES.** When Gateway queries `VirtualDNSServiceAddr`, `cloudflared` immediately proxies the DNS request to `127.0.0.1:53`. CoreDNS returns `127.0.0.1`. Gateway receives `127.0.0.1`, maps it to the synthetic IP, and later forwards the TCP flow with `Dest: "127.0.0.1:<port>"`.
2. **Loopback reachability:** Perfect. `cloudflared` dials `127.0.0.1:<port>` over loopback directly to Envoy in the same pod.
3. **Wildcard support:** Excellent. CoreDNS `hosts` plugin natively supports wildcards (`*.internal.example`). CoreDNS `template` plugin can handle arbitrary pattern matching.
4. **Platform prerequisites:**
   - Pod keeps standard `dnsPolicy: ClusterFirst` (so `cloudflared` and Envoy resolve external/cluster addresses normally).
   - Corefile mounted via ConfigMap.
   - CoreDNS `reload` plugin enables dynamic updates without restarting the pod.
5. **Failure modes & latency:** Local in-memory resolution (<1ms). If CoreDNS crashes, Gateway gets a DNS timeout.
6. **Interaction with Access / WARP:** Uses standard `/zerotrust/routes/hostname`.

---

## Option 3: cluster CoreDNS

### Description
Modify the cluster-wide CoreDNS ConfigMap (`kube-system/coredns`) by adding `hosts` or `rewrite` rules pointing `admin.internal.example` to the Envoy Service ClusterIP.

### Evaluation
1. **Does it work at all?** **YES.** Because `cloudflared` defaults to using the nameserver in `/etc/resolv.conf` (which points to kube-dns `10.96.0.10:53`), cluster CoreDNS answers Gateway's DNS query with Envoy's ClusterIP.
2. **Loopback reachability:** Reaches Envoy via the Service ClusterIP (not loopback `127.0.0.1`).
3. **Wildcard support:** Supported via CoreDNS `rewrite` or `template` plugins.
4. **Platform prerequisites:** Requires `cluster-admin` access to modify `kube-system/coredns`.
5. **Failure modes & risks:**
   - **Severe blast radius:** Any syntax error or misconfiguration in `kube-system/coredns` breaks DNS resolution for the entire Kubernetes cluster.
   - Cloud providers (EKS, AKS, GKE) frequently overwrite or restrict custom edits to cluster CoreDNS.
   - Multi-tenant unsuitability: Operator cannot be installed by non-cluster-admins.

---

## Option 4: Gateway DNS override + CIDR route (no hostname route)

### Description
Bypass Cloudflare Private Hostname routes entirely:
1. Create a Cloudflare Tunnel CIDR route (`POST /accounts/{account_id}/teamnet/routes`) for the Envoy Service ClusterIP (e.g. `10.96.123.45/32`) or Service CIDR (`10.96.0.0/12`).
2. Create a Cloudflare Gateway DNS policy (`POST /accounts/{account_id}/gateway/rules`):
   - `filters: ["dns"]`
   - `action: "override"`
   - `traffic: "dns.fqdn == \"admin.internal.example\""`
   - `rule_settings`:
     ```json
     {
       "override_ips": ["10.96.123.45"]
     }
     ```

### Evaluation
1. **Does it work at all?** **YES.** When the client queries `admin.internal.example`, Gateway directly returns `10.96.123.45`. The client opens a TCP connection to `10.96.123.45:443`. WARP routes the flow over the tunnel. `cloudflared` receives `Dest: "10.96.123.45:443"` and dials the ClusterIP directly. **No in-cluster DNS resolution occurs.**
2. **Loopback reachability:** Dials the ClusterIP via kube-proxy / CNI, not `127.0.0.1`.
3. **Wildcard support:** Gateway DNS rule traffic expressions support wildcards: `dns.fqdn.matches(".*\\.internal\\.example")`.
4. **Platform prerequisites:**
   - Gateway DNS filtering must be active on all devices (WARP mode: "Gateway with DoH" or "Traffic and DNS").
   - WARP Split Tunnels must include the Kubernetes Service CIDR or specific ClusterIP.
5. **Downsides & Access interactions:**
   - If Access is configured with `destinations[].type: "cidr"`, any traffic to the ClusterIP matches, collapsing granular per-hostname policies unless SNI is used.
   - If the Kubernetes Service is deleted and recreated, the ClusterIP changes, requiring API updates to Gateway DNS rules and Tunnel CIDR routes.

---

## Option 5: Service FQDN as hostname

### Description
Register the Kubernetes Service FQDN directly as the private hostname route in Cloudflare:
`admin-envoy.flareway.svc.cluster.local`

### Evaluation
1. **Does it work at all?** **YES.** Cloudflared queries kube-dns via its default `VirtualDNSServiceAddr` path. Kube-dns natively resolves `admin-envoy.flareway.svc.cluster.local` to Envoy's ClusterIP.
2. **Loopback reachability:** Dials ClusterIP.
3. **Wildcard support:** Supported at DNS level by kube-dns only for headless services; does not support arbitrary custom domains.
4. **UX & TLS Disadvantages:**
   - **Poor UX:** Users must navigate to `https://admin-envoy.flareway.svc.cluster.local`.
   - **TLS Certificate Obstacle:** Public Certificate Authorities (Let's Encrypt, DigiCert) will not issue certificates for `.cluster.local` or `.local` domains. An enterprise internal CA must be installed on all client devices.

---

## Comparison Table

| Criteria | Option 1: hostAliases | Option 2: Pod-Local DNS Sidecar | Option 3: Cluster CoreDNS | Option 4: Gateway DNS Override + CIDR | Option 5: Service FQDN |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Works with cloudflared?** | ❌ No (`NXDOMAIN`) | ✅ **Yes** | ✅ Yes | ✅ Yes | ✅ Yes |
| **Dials `127.0.0.1` (Pod Loopback)?**| N/A | ✅ **Yes** | ❌ No (ClusterIP) | ❌ No (ClusterIP) | ❌ No (ClusterIP) |
| **Wildcard Support (`*.domain`)** | ❌ No | ✅ **Yes** (Corefile hosts/regex) | ✅ Yes (rewrite) | ✅ Yes (`dns.fqdn.matches`) | ❌ No |
| **Dynamic Updates (No Pod Restart)** | ❌ No (Immutable PodSpec)| ✅ **Yes** (ConfigMap inotify reload)| ✅ Yes (ConfigMap reload) | ✅ Yes (Cloudflare API) | ❌ N/A |
| **Required Permissions / Blast Radius** | None (broken) | **Pod-local only** (Zero blast radius) | `cluster-admin` (Cluster-wide blast radius) | Zero Trust Gateway & Route Admin | None |
| **Access `destinations[].type`** | N/A | `hostname` | `hostname` | `hostname` (SNI) or `cidr` | `hostname` |
| **Client Split-Tunnel Config** | N/A | Synthetic Range (`172.64.128.0/20`) | Synthetic Range (`172.64.128.0/20`) | Service CIDR (`10.96.0.0/12`) | Synthetic Range (`172.64.128.0/20`) |

---

## TLS/Access on the private path

### 1. TLS Termination & Inspection
- **Without Gateway TLS Decryption:**
  Cloudflare Edge operates as a pure L4 proxy. TLS is end-to-end encrypted between the client and Envoy. Cloudflare Edge does **not** terminate TLS. Envoy must serve a TLS certificate that the client device trusts.
- **With Gateway TLS Decryption:**
  Cloudflare Edge terminates client TLS using the Cloudflare Zero Trust managed root certificate. Gateway inspects the plaintext HTTP request, then initiates a separate TLS handshake to Envoy. Envoy can present an internal certificate (trusted by Gateway or permitted via `untrusted certificate: Pass through`).

### 2. Access JWT Assertion Injection (`Cf-Access-Jwt-Assertion`)
- Direct quotation from Cloudflare Documentation (`self-hosted-private-app`):
  > *"If Gateway TLS decryption is turned on and a user is accessing an HTTPS application on port 443, Cloudflare Access will present a login page in the browser and issue an application token to your origin. This is the same cookie-based authentication flow used by self-hosted public apps. If Gateway TLS decryption is turned off, session management is handled in the Cloudflare One Client instead of in the browser."*
- **Verdict:** Without Gateway TLS decryption, Cloudflare Edge **cannot inject `Cf-Access-Jwt-Assertion`** into HTTPS traffic because it cannot modify the encrypted L7 payload. To receive user identity headers at Envoy on a private path, Gateway TLS decryption must be turned on.

### 3. Loopback Dialing Constraints
Inspection of `cloudflared` source (`ingress/config.go`, `config/configuration.go`, `ingress/origin_dialer.go`):
- `WarpRoutingConfig` only controls `ConnectTimeout`, `MaxActiveFlows`, and `TCPKeepAlive`.
- `originRequest.ipRules` is **only** evaluated for Bastion / SOCKS5 proxies (`ingress/ingress.go:271`), never for WARP routing.
- `cloudflared` places **no restrictions** on dialing `127.0.0.1` or link-local addresses for WARP flows.
- *Note on Bogon / Gateway filtering:* If Cloudflare Gateway ever disallows `127.0.0.1` as a resolved private IP from the DNS query [unverified], the DNS sidecar can return the pod's IP (`status.podIP` via Downward API) or the Envoy Service ClusterIP. When `cloudflared` dials the pod IP, the Linux kernel network stack routes it directly via the local `eth0` interface without leaving the pod network namespace.

---

## Recommendation candidates (ranked, with evidence)

### Rank 1: Option 2 — Pod-Local DNS Sidecar + `TUNNEL_DNS_RESOLVER_ADDRS=127.0.0.1:53` (Primary Recommendation)
- **Evidence:**
  - `cloudflared` natively exposes `TUNNEL_DNS_RESOLVER_ADDRS` (`flags.VirtualDNSServiceResolverAddresses`), which overrides the dynamic `/etc/resolv.conf` peeker and points virtual DNS queries to `127.0.0.1:53`.
  - Preserves 100% loopback isolation: traffic goes directly to `127.0.0.1:<port>` on Envoy in the same pod.
  - Zero cluster-wide permissions: works in unprivileged namespaces without touching cluster CoreDNS.
  - CoreDNS sidecar supports wildcards (`*.internal.example`) and dynamic reloading via ConfigMap without pod restarts.

### Rank 2: Option 4 — Cloudflare Gateway DNS Override + Tunnel CIDR Route (Fallback / Alternative)
- **Evidence:**
  - Entirely eliminates DNS inside the cluster: Gateway returns the Envoy Service ClusterIP directly; WARP routes the flow over the tunnel; `cloudflared` dials the ClusterIP via `DialContext`.
  - Avoids running a DNS sidecar container.
  - Downside: Requires managing Gateway DNS rules alongside Tunnel routes, requires Service CIDR in WARP split tunnels, and requires Gateway DNS filtering on client devices.

### Rank 3: Option 5 — Service FQDN as Private Hostname (Development / Smoke Testing)
- **Evidence:**
  - Requires zero extra components; works out of the box because kube-dns naturally resolves `*.svc.cluster.local`.
  - Downside: Terrible UX and difficult TLS trust model for end users.

### Rejected: Option 1 (hostAliases) & Option 3 (Cluster CoreDNS)
- **Option 1 is rejected** because `cloudflared` does not use local `/etc/hosts` for WARP virtual DNS queries (`NXDOMAIN`).
- **Option 3 is rejected** due to extreme blast radius, cluster-admin requirements, and cloud provider incompatibilities.

---

## Sources

1. **Cloudflared Repository (`github.com/cloudflare/cloudflared` at `f11dea9`):**
   - `ingress/origins/dns.go`: Implementation of `VirtualDNSServiceAddr` (`2606:4700:0cf1:2000::1:53`), `DNSResolverService`, and `peekDial`.
   - `cmd/cloudflared/flags/flags.go`: Definition of `VirtualDNSServiceResolverAddresses = "dns-resolver-addrs"`.
   - `cmd/cloudflared/tunnel/subcommands.go`: Binding of `TUNNEL_DNS_RESOLVER_ADDRS`.
   - `proxy/proxy.go`: `ProxyTCP` parsing `req.Dest` as `netip.AddrPort`.
   - `ingress/origin_dialer.go`: `Dialer.DialTCP` invoking `net.Dialer.DialContext`.
2. **Cloudflare Documentation:**
   - [Connect a private hostname](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/private-net/cloudflared/connect-private-hostname/)
   - [Private DNS](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/private-net/cloudflared/private-dns/)
   - [Self-hosted private applications](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/non-http/self-hosted-private-app/)
   - [DNS policies](https://developers.cloudflare.com/cloudflare-one/traffic-policies/dns-policies/)
3. **Cloudflare Architecture Blog:**
   - [Under the hood: how hostname routing works](https://blog.cloudflare.com/tunnel-hostname-routing/)
4. **Cloudflare OpenAPI Specifications:**
   - Endpoint `/accounts/{account_id}/zerotrust/routes/hostname`
   - Endpoint `/accounts/{account_id}/gateway/rules` (`override_ips`, `override_host`)

---

## Open Questions

1. **Gateway Bogon Handling for `127.0.0.1`:** Does Cloudflare Gateway's internal resolver accept `127.0.0.1` as a valid private DNS answer from the tunnel, or does it reject `127.0.0.1` as a loopback/bogon address? If Gateway rejects `127.0.0.1`, configuring the DNS sidecar to respond with the Pod's own IP (`status.podIP`) is the recommended mitigation (since Linux routes pod IP traffic directly on `eth0` without leaving the pod).
2. **Gateway TLS Decryption Requirement for Envoy:** If Flareway relies on `Cf-Access-Jwt-Assertion` for in-cluster RBAC/auth, users must be informed that Gateway TLS Decryption must be enabled in Zero Trust settings.
