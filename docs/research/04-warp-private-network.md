# Cloudflare WARP Client, Device Management & Private Networking Research (2026-09-12)

## Summary (10 bullets max)
1. **Device Settings Profiles**: Default profile is accessed at `GET/PATCH /accounts/{id}/devices/policy`; custom profiles use `GET/POST /accounts/{id}/devices/policy` and `GET/PATCH/DELETE /accounts/{id}/devices/policy/{policy_id}` (list at `GET /accounts/{id}/devices/policies`).
2. **Split Tunnel Replace Semantics**: Split tunnel endpoints (`/devices/policy/[{id}/]exclude` and `include`) use `PUT` with a full array; there is no per-entry add/delete API (whole-list replace semantics).
3. **Split Tunnel Exclusivity & Limits**: A profile is strictly either in `include` or `exclude` mode (mutually exclusive). Account limit is 1,000 combined Split Tunnel and Local Domain Fallback entries per profile, with 10,000 chars per profile match expression.
4. **Settings Ownership**: Three distinct tiers exist: Access Organization (`/access/organizations` for `warp_auth_session_duration`), Account Device Settings (`/devices/settings` for proxy toggles and virtual IP), and Device Profiles (`/devices/policy` for client UI, split tunnels, and fallback).
5. **Tunnel Routes & Virtual Networks**: CIDR routes (`/teamnet/routes`) bind a CIDR to a tunnel and an optional `virtual_network_id` (VRF/VPC isolation). Overlapping CIDRs are strictly rejected within the same Virtual Network. Limit is 1,000 routes and 1,000 virtual networks per account.
6. **Private Hostname Routes (GA)**: Steers internal hostnames (`wiki.internal.local`) down a Cloudflare Tunnel using synthetic Initial Resolved IPs (`172.64.128.0/20` IPv4, `2606:4700:0cf1:4000::/64` IPv6) via API `/accounts/{id}/zerotrust/routes/hostname`.
7. **Identity-Gated Private Apps**: Gateway network policies (`/gateway/rules`, L4) evaluate *first*; Access self-hosted applications with `destinations[].type = "private"` (L7/L4 with hostname/CIDR + port range) evaluate *second* and are Cloudflare's recommended model for Zero Trust service-level policies.
8. **Client-Side Hostname Routing**: In Exclude mode, public DNS proxied CNAME hostnames resolve to Cloudflare Anycast IPs and flow to Edge without split tunnel additions. In Include mode, either the hostname or the synthetic CIDR (`172.64.128.0/20`) must be explicitly included.
9. **Terraform v5 Parity**: Terraform provider v5.25.0 provides `cloudflare_zero_trust_device_default_profile`, `cloudflare_zero_trust_device_custom_profile`, `cloudflare_zero_trust_device_settings`, `cloudflare_zero_trust_organization`, `cloudflare_zero_trust_tunnel_cloudflared_route`, and `cloudflare_zero_trust_tunnel_cloudflared_virtual_network`.
10. **Operator Precedents**: Tailscale Operator uses `Connector` CRD (`spec.subnetRouter.advertiseRoutes`, `exitNode`) and service annotations; `StringKe/cloudflare-operator` uses `NetworkRoute`, `VirtualNetwork`, and `DeviceSettingsPolicy` (featuring `autoPopulateFromRoutes`).

---

## Device profiles & split tunnel

### Endpoint Table
Device settings profiles control the Cloudflare One Client (WARP) behavior, tunnel protocol, split tunneling, and local domain fallback.

| Target | HTTP Method | API Path | Description |
| :--- | :--- | :--- | :--- |
| **Default Profile** | `GET` | `/accounts/{account_id}/devices/policy` | Get default device settings profile |
| **Default Profile** | `PATCH` | `/accounts/{account_id}/devices/policy` | Update default device settings profile |
| **Custom Profiles** | `GET` | `/accounts/{account_id}/devices/policies` | List all custom device settings profiles |
| **Custom Profiles** | `POST` | `/accounts/{account_id}/devices/policy` | Create a custom device settings profile |
| **Custom Profile** | `GET` | `/accounts/{account_id}/devices/policy/{policy_id}` | Get custom profile by ID |
| **Custom Profile** | `PATCH` | `/accounts/{account_id}/devices/policy/{policy_id}` | Update custom profile by ID |
| **Custom Profile** | `DELETE` | `/accounts/{account_id}/devices/policy/{policy_id}` | Delete custom profile by ID |
| **Default Split Exclude** | `GET` / `PUT` | `/accounts/{account_id}/devices/policy/exclude` | Get / Replace default split tunnel exclude list |
| **Default Split Include** | `GET` / `PUT` | `/accounts/{account_id}/devices/policy/include` | Get / Replace default split tunnel include list |
| **Default Fallback** | `GET` / `PUT` | `/accounts/{account_id}/devices/policy/fallback_domains` | Get / Replace default local domain fallback list |
| **Custom Split Exclude** | `GET` / `PUT` | `/accounts/{account_id}/devices/policy/{policy_id}/exclude` | Get / Replace custom profile split tunnel exclude list |
| **Custom Split Include** | `GET` / `PUT` | `/accounts/{account_id}/devices/policy/{policy_id}/include` | Get / Replace custom profile split tunnel include list |
| **Custom Fallback** | `GET` / `PUT` | `/accounts/{account_id}/devices/policy/{policy_id}/fallback_domains` | Get / Replace custom profile local domain fallback list |

*Note regarding `/devices/settings/policies`:* The official API path in Cloudflare Zero Trust remains `/accounts/{account_id}/devices/policy` (for single/default profile operations) and `/accounts/{account_id}/devices/policies` (for listing profiles). There is no separate `/devices/settings/policies` route in the 2026 API reference.

### Whole-Object Replace Semantics (PUT)
All split-tunnel and fallback domain manipulation endpoints utilize `PUT` with an array payload:
- Split tunnel payload: Array of `SplitTunnelEntry`:
  ```json
  [
    { "address": "10.0.0.0/8", "description": "Private subnet" },
    { "host": "internal.example.com", "description": "Internal domain" }
  ]
  ```
- Either `address` (CIDR) or `host` (domain name) must be specified per entry, never both.
- **No item-level endpoints**: There are no `POST /devices/policy/.../exclude/entries` or `DELETE .../entries/{id}` endpoints. Any update must read the current array, modify it in memory, and `PUT` the entire list. In Terraform and controller-runtime, this creates a classic "single-writer" tension where multiple routes attempting to reconcile into split tunnels must be aggregated into a single reconciled object.

### Include vs. Exclude Exclusivity
- Include and Exclude modes are strictly **mutually exclusive** per device profile.
- A profile cannot declare both an `include` and an `exclude` list.
- In `exclude` mode (default), all device traffic enters Cloudflare Gateway *except* destinations matching the exclude list.
- In `include` mode, *only* traffic destined for addresses/domains matching the include list enters the WARP tunnel; all other traffic bypasses WARP and heads direct-to-internet.

### Device Profile Fields
- `name` (string): Profile name.
- `description` (string): Human-readable description.
- `match` (string): Wirefilter expression determining device eligibility (e.g. `identity.email matches ".*@company.com" && os.name == "mac"`).
- `precedence` (number): Order of evaluation (lower number = higher priority).
- `enabled` (boolean): Whether the profile is currently active.
- `default` (boolean, read-only): Whether this is the fallback default policy.
- `switch_locked` (boolean): Locks the client switch to prevent users from disconnecting.
- `captive_portal` (number): Timeout in seconds to remain disabled during captive portal detection.
- `allow_mode_switch` (boolean): Whether users can toggle between Gateway/WARP modes.
- `allow_updates` (boolean): Controls in-client update notifications.
- `allowed_to_leave` (boolean): Allows users to log out / unenroll from the organization.
- `auto_connect` (number): Minutes to wait before automatically reconnecting WARP after manual disable (0 = remain disconnected).
- `disable_auto_fallback` (boolean): Disables automatic fallback to local system DNS if fallback domain DNS servers are unreachable.
- `exclude_office_ips` (boolean): Automatically injects Microsoft 365 / corporate office IP bypasses into split tunnel exclusions.
- `service_mode_v2` (object: `{ mode: "warp" | "1.1.1.1" | "proxy" | "posture_only", port?: number }`).
- `support_url` (string): Custom support link in the WARP client GUI.
- `lan_allow_minutes` (number): Allowed duration for local LAN bypass.
- `lan_allow_subnet_size` (number): Maximum subnet mask size allowed for local LAN bypass (e.g. `24`).
- `register_interface_ip_with_dns` (boolean): Registers WARP client virtual adapter IP with local DNS servers.
- `sccm_vpn_boundary_support` (boolean): Modifies network adapter description for Windows SCCM detection.
- `tunnel_protocol` (string): `"wireguard"` or `"masque"` (HTTP/3-based transport).
- `virtual_networks` (object): Configures `{ default: "<vnet_id>", allowed: ["<vnet_id>"] }` for client profile.
- `dns_search_suffixes` (array of `{ suffix: string, description?: string }`): Search domains pushed to clients.

### Account Limits
- **Split Tunnel & Fallback entries**: Combined max **1,000** entries per device profile.
- **Match expression length**: Max **10,000** characters per device profile match expression.
- **Device IP profiles**: Max **30** per account.

---

## Org vs account-device vs profile settings

Cloudflare Zero Trust splits settings across three distinct API layers. Operators must avoid conflating account-wide network toggles with per-user device client configurations.

| Setting / Field Name | Owning API Scope | Exact API Endpoint | Description / Purpose |
| :--- | :--- | :--- | :--- |
| `warp_auth_session_duration` | **Access Organization** | `GET/PUT /accounts/{id}/access/organizations` | Global re-authentication duration for Access apps protected by WARP identity (e.g. `"24h"`, `"720h"`). |
| `allow_authenticate_via_warp`| **Access Organization** | `GET/PUT /accounts/{id}/access/organizations` | Enables WARP client session credentials as an IdP for Access applications. |
| `warp_auth_non_browser_401`  | **Access Organization** | `GET/PUT /accounts/{id}/access/organizations` | Returns HTTP 401 instead of 302 redirect for non-browser CLI/API requests when WARP auth fails. |
| `auth_domain` / `name`       | **Access Organization** | `GET/PUT /accounts/{id}/access/organizations` | Team domain (`<team>.cloudflareaccess.com`) and organization display name. |
| `gateway_proxy_enabled`      | **Account Device Settings** | `GET/PUT/PATCH /accounts/{id}/devices/settings` | Enables Cloudflare Gateway L4 TCP proxy filtering across all enrolled devices. |
| `gateway_udp_proxy_enabled`  | **Account Device Settings** | `GET/PUT/PATCH /accounts/{id}/devices/settings` | Enables Cloudflare Gateway L4 UDP proxy filtering (required for private DNS & UDP routing). |
| `root_certificate_installation_enabled` | **Account Device Settings** | `GET/PUT/PATCH /accounts/{id}/devices/settings` | Instructs WARP client to install Cloudflare root CA into local trust store for TLS inspection. |
| `use_zt_virtual_ip`          | **Account Device Settings** | `GET/PUT/PATCH /accounts/{id}/devices/settings` | Assigns an isolated Zero Trust virtual IP (CGNAT IPv4) to each client adapter. |
| `disable_for_time`           | **Account Device Settings** | `GET/PUT/PATCH /accounts/{id}/devices/settings` | Time limit in seconds for administrator one-time override code bypasses. |
| `external_emergency_signal_*`| **Account Device Settings** | `GET/PUT/PATCH /accounts/{id}/devices/settings` | External HTTPS probe URL/fingerprint to automatically disconnect all WARP clients during outages. |
| `switch_locked`              | **Device Profile Settings** | `GET/PATCH /accounts/{id}/devices/policy[/{id}]` | Restricts user ability to toggle off WARP connection on targeted device groups. |
| `tunnel_protocol`            | **Device Profile Settings** | `GET/PATCH /accounts/{id}/devices/policy[/{id}]` | Transport protocol (`wireguard` vs `masque`) for targeted device groups. |
| `auto_connect` / `captive_portal` | **Device Profile Settings** | `GET/PATCH /accounts/{id}/devices/policy[/{id}]` | Auto-reconnection timer and captive portal handling. |
| `service_mode_v2`            | **Device Profile Settings** | `GET/PATCH /accounts/{id}/devices/policy[/{id}]` | Client operating mode (`warp`, `1.1.1.1`, `proxy`, `posture_only`). |
| `exclude` / `include`        | **Device Profile Settings** | `PUT /devices/policy[/{id}]/exclude\|include` | Subnet and hostname split tunnel routing table. |
| `fallback_domains`           | **Device Profile Settings** | `PUT /devices/policy[/{id}]/fallback_domains` | Local DNS suffix bypass exceptions. |

---

## Tunnel routes & virtual networks

### Tunnel Routes API (`/accounts/{account_id}/teamnet/routes`)
Tunnel routes define private IP CIDRs routed down an outbound-only Cloudflare Tunnel (`cloudflared`):
- `POST /accounts/{account_id}/teamnet/routes`: Create route.
- `GET /accounts/{account_id}/teamnet/routes`: List routes.
- `PATCH /accounts/{account_id}/teamnet/routes/{route_id}`: Update comment or virtual network.
- `DELETE /accounts/{account_id}/teamnet/routes/{route_id}`: Delete route.
- `GET /accounts/{account_id}/teamnet/routes/ip/{ip}`: Lookup active route for a given destination IP.

**Model Fields (`NetworkRoute` / `Teamnet`):**
- `id` (UUID string): Route ID.
- `network` (string): IPv4 or IPv6 CIDR (e.g. `10.0.0.0/16`, `172.20.0.1/32`).
- `tunnel_id` (UUID string): Cloudflare Tunnel handling the route.
- `virtual_network_id` (UUID string, optional): Target Virtual Network. If omitted, assigned to the account's `default` virtual network.
- `comment` (string, max 100 chars): Descriptive note.
- `tun_type` (enum): `"cfd_tunnel"`, `"warp_connector"`, `"warp"`, `"magic"`, `"ip_sec"`, `"gre"`, `"cni"`.
- `tunnel_name` / `virtual_network_name` (string, read-only): Display names.

### Virtual Networks API (`/accounts/{account_id}/teamnet/virtual_networks`)
Virtual Networks function as cloud VRFs (Virtual Routing and Forwarding) or VPCs:
- `POST /accounts/{account_id}/teamnet/virtual_networks`
- `GET /accounts/{account_id}/teamnet/virtual_networks`
- `PATCH /accounts/{account_id}/teamnet/virtual_networks/{virtual_network_id}`
- `DELETE /accounts/{account_id}/teamnet/virtual_networks/{virtual_network_id}`

**Model Fields (`VirtualNetwork`):**
- `id` (UUID string): VNet identifier.
- `name` (string, max 256 chars): Unique display name (e.g. `production-vnet`, `staging-vnet`).
- `comment` (string, max 256 chars): Description.
- `is_default_network` (boolean): Whether this VNet is the default for the account (only one default allowed).

### Overlap Rules & Limits
1. **CIDR Overlap Isolation**:
   - The same CIDR range (e.g. `10.0.0.0/16`) can be registered multiple times in a single Cloudflare account **only if** each instance is attached to a distinct `virtual_network_id`.
   - Within the same Virtual Network, route collision/overlap is strictly rejected by the API.
2. **Account Limits**:
   - Total CIDR and Hostname routes per account: **1,000** (shared with Cloudflare Mesh).
   - Virtual Networks per account: **1,000**.
   - Cloudflare Tunnels per account: **1,000**.
   - Active `cloudflared` replicas per tunnel: **25**.
3. **CLI Equivalents (`cloudflared`)**:
   - Add route: `cloudflared tunnel route ip add [--vnet <vnet_name>] <cidr> <tunnel_name|id>`
   - List routes: `cloudflared tunnel route ip list`
   - VNet management: `cloudflared tunnel vnet add <name>`, `cloudflared tunnel vnet list`, `cloudflared tunnel vnet delete <name>`

---

## Private hostname routes (new)

### Overview & Status
In late 2025/2026, Cloudflare introduced **Private Hostname Routing** (now **General Availability (GA)**). This feature allows organizations to steer traffic for internal domain names (e.g. `wiki.internal.local`, `*.corp.internal`) down a Cloudflare Tunnel *without* needing to expose public DNS records or manage static internal IP routes on client split tunnels.

### Architecture & Mechanics
1. **Initial Resolved IPs**:
   - When a client queries a private hostname, Cloudflare Gateway DNS intercepts the lookup and returns an internal synthetic IP from a reserved address pool:
     - **IPv4**: `172.64.128.0/20` (default)
     - **IPv6**: `2606:4700:0cf1:4000::/64` (default)
   - *Legacy Note*: Prior implementations allocated IPs in CGNAT space (`100.80.0.0/16` or `100.64.0.0/10`). Cloudflare migrated the default to public address space (`172.64.128.0/20`) to eliminate Chrome Local Network Access (LNA) security blocks introduced in Chrome 140–146+.
2. **Egress Translation**:
   - Traffic sent by the client to `172.64.128.x` is captured by WARP, transmitted to Cloudflare's edge, and routed down the designated Cloudflare Tunnel.
   - The `cloudflared` agent in the cluster resolves the actual private origin IP via local cluster DNS (`kube-dns` / `CoreDNS`) or internal DNS server.

### Minimum Version Requirements
- **WARP Client**: Windows, macOS, Linux: `>= 2025.4.929.0`; iOS: `>= 1.11`; Android/ChromeOS: `>= 2.4.2`.
- **cloudflared**: `>= 2025.7.0`.
- **Gateway Prerequisites**: `gateway_proxy_enabled = true` and `gateway_udp_proxy_enabled = true` (in `/devices/settings`).

### API Endpoints (`/accounts/{account_id}/zerotrust/routes/hostname`)
Dedicated REST endpoints manage hostname routes directly under the Zero Trust network namespace:
- `GET /accounts/{account_id}/zerotrust/routes/hostname`: List hostname routes.
- `POST /accounts/{account_id}/zerotrust/routes/hostname`: Create hostname route.
- `GET /accounts/{account_id}/zerotrust/routes/hostname/{hostname_route_id}`: Inspect route.
- `PATCH /accounts/{account_id}/zerotrust/routes/hostname/{hostname_route_id}`: Update comment/hostname.
- `DELETE /accounts/{account_id}/zerotrust/routes/hostname/{hostname_route_id}`: Delete route.

**Payload Schema:**
```json
{
  "hostname": "k8s-ingress.internal.company.com",
  "tunnel_id": "f70ff985-a4ef-4643-bbbc-4a0ed4fc8415",
  "comment": "Internal Kubernetes ingress route"
}
```

---

## Identity-gated private access options

When securing private infrastructure reachable over tunnels, Cloudflare provides two distinct enforcement layers:

### 1. Gateway Network Policies (`/accounts/{id}/gateway/rules`)
- **Layer**: L4 (TCP/UDP/ICMP).
- **Traffic Filter Syntax**: Wirefilter expressions matching on network primitives, SNI, or Identity:
  `traffic = "net.dst.ip in {10.0.0.0/8 172.64.128.0/20} && net.port in {80 443 8080}"`
  `identity = "identity.groups.name in {\"DevOps\"} && device_posture.checks.passed in {\"uuid\"}"`
- **Actions**: `allow`, `block`, `audit_ssh`, `l4_override`.
- **Session Check**: `rule_settings.check_session = { enforce: true, duration: "8h" }`.

### 2. Access Self-Hosted Applications with Private Destinations (`/accounts/{id}/access/apps`)
- **Layer**: L4 and L7 Zero Trust Application security.
- **Application Structure**: Configured with `type = "self_hosted"` and the `destinations` attribute list.
- **Destinations Schema**:
  ```json
  "destinations": [
    {
      "type": "private",
      "hostname": "db.internal.local",
      "cidr": "10.244.0.0/16",
      "l4_protocol": "tcp",
      "port_range": "5432",
      "vnet_id": "optional-vnet-uuid"
    }
  ]
  ```
- **Capabilities**: Directly attaches Access Policies (`policies[]` with `include`, `require`, `exclude`), IdP selection (`allowed_idps`), MFA constraints, and service token authentication.

### Evaluation Order & Architectural Recommendation
1. **Evaluation Precedence**:
   - When a packet arrives from WARP, **Gateway Network Policies are evaluated first**.
   - If Gateway permits the traffic, Cloudflare evaluates **Access Application Policies second**.
   - To delegate identity checks entirely to Access, administrators create a Gateway rule: `Access Private App is Present | Action: Allow`.
2. **Recommendation for Flareway Operator**:
   - **Access Self-Hosted Private Applications** are the modern, recommended abstraction for application-level / route-level access. They provide fine-grained identity binding, per-app session timeouts, and audit logging per service.
   - **Gateway Network Policies** should be reserved for coarse cluster-wide firewall boundaries (e.g. default-deny egress rules, VPC egress controls).
3. **Plan Requirements**:
   - Access Private Applications and Gateway Network Policies require **Zero Trust Standard** or **Zero Trust Enterprise** plans.
4. **WARP Connector vs. cloudflared**:
   - **cloudflared**: Lightweight user-space daemon providing application-layer reverse tunnels. Unidirectional outbound connectivity (users reach services behind the tunnel; services cannot initiate connections back to user devices). Ideal for ingress into Kubernetes clusters.
   - **WARP Connector** (rebranded as **Cloudflare Mesh**): Linux host/kernel-level router utilizing WireGuard/MASQUE interfaces. Enables bidirectional, site-to-site, subnet-to-subnet, and server-to-client routing. Heavyweight for standard Kubernetes ingress; cloudflared is preferred for Gateway API ingress.

---

## Client-side hostname/include semantics

### Behavior for Public Proxied CNAME vs. Private Hostnames
When Flareway exposes a private hostname (e.g. `cc-lb.runbear.io`) via an Access Application backed by a public DNS CNAME pointing to `<tunnel-id>.cfargotunnel.com`:
- **In Exclude Mode (Default WARP profile)**:
  1. The client resolves `cc-lb.runbear.io` via standard DNS / Gateway DoH.
  2. DNS returns Cloudflare public Anycast edge IPs (`104.16.x.x` / `172.67.x.x`).
  3. Because Cloudflare Anycast IPs are **not** in the default Split Tunnel exclude list (default exclusions only cover RFC 1918, CGNAT `100.64.0.0/10`, and link-local ranges), traffic is routed down the WARP tunnel to Cloudflare Edge.
  4. Cloudflare Access intercepts the connection, evaluates WARP identity/posture, and proxies down the tunnel.
  5. **Result**: In Exclude mode, `cc-lb.runbear.io` **does not** need to be in the Split Tunnel exclude or include list.
- **In Include Mode (Strict Zero Trust profile)**:
  1. Only traffic whose destination IP or hostname matches the `include` list is sent to Cloudflare; everything else bypasses WARP directly to the user's local network gateway.
  2. If `cc-lb.runbear.io` is *not* in the include list, the client routes the TCP handshake direct to the public internet. While Cloudflare Edge still answers, traffic bypasses Gateway inspection and device posture metadata carried inside the WARP tunnel may be lost.
  3. **Result**: In Include mode, either:
     - The explicit domain `cc-lb.runbear.io` (or wildcard `*.runbear.io`) must be added as `{ host: "cc-lb.runbear.io" }` to the profile's `include` list, OR
     - If using the new Private Hostname route model, the Initial Resolved IP range (`172.64.128.0/20`) must be in the `include` list. Adding `172.64.128.0/20` once automatically covers all private hostname routes.

### Interactions with Local Domain Fallback
- Local Domain Fallback (`/devices/policy/.../fallback_domains`) configures domain suffixes (e.g. `internal.corp`, `local`) that **bypass Cloudflare Gateway DNS** and resolve via local LAN DHCP servers.
- **Critical Caveat**: If an internal hostname route (e.g. `api.internal.local`) matches a suffix in Fallback Domains, the client will send DNS queries to local Wi-Fi/VPN DNS rather than Cloudflare Gateway. Gateway will never return the synthetic `172.64.128.0/20` IP, and routing will fail. Internal private hostnames managed by Cloudflare **must not** overlap with fallback domain suffixes.

### Interactions with `register_interface_ip_with_dns`
- Setting `register_interface_ip_with_dns: true` forces the client OS to register its local WARP interface IP (`100.96.x.x` or virtual IP) with on-premises DNS servers (Active Directory/Dynamic DNS).
- This is only relevant for reverse-lookup/device discovery within on-premises networks and has no effect on ingress routing through Cloudflare Tunnels into Kubernetes.

---

## SDK / Terraform map

### Terraform Provider v5.25.0 Resource Mapping
In version 5 of the Cloudflare Terraform provider (`cloudflare/cloudflare`), Zero Trust resources have been standardized under the `cloudflare_zero_trust_*` namespace.

| Terraform v5 Resource Name | Underlying Cloudflare API Endpoint | Mutation Semantics |
| :--- | :--- | :--- |
| `cloudflare_zero_trust_device_default_profile` | `PATCH /accounts/{id}/devices/policy` | Partial update for profile settings; inline `exclude`/`include` attributes perform whole-list replace. |
| `cloudflare_zero_trust_device_custom_profile` | `POST /accounts/{id}/devices/policy`<br>`PATCH/DELETE .../devices/policy/{id}` | Per-resource lifecycle; inline `exclude`/`include` attributes perform whole-list replace. |
| `cloudflare_zero_trust_device_default_profile_local_domain_fallback` | `PUT /accounts/{id}/devices/policy/fallback_domains` | **Whole-list replace** (`domains` set). Replaces all fallback domains for default profile. |
| `cloudflare_zero_trust_device_custom_profile_local_domain_fallback` | `PUT /accounts/{id}/devices/policy/{id}/fallback_domains` | **Whole-list replace** (`domains` set). Replaces all fallback domains for specified profile. |
| `cloudflare_zero_trust_device_settings` | `PUT/PATCH /accounts/{id}/devices/settings` | Account-level singleton (`gateway_proxy_enabled`, `use_zt_virtual_ip`, etc.). |
| `cloudflare_zero_trust_organization` | `PUT /accounts/{id}/access/organizations` | Account-level singleton (`warp_auth_session_duration`, `allow_authenticate_via_warp`). |
| `cloudflare_zero_trust_tunnel_cloudflared_route` | `POST /accounts/{id}/teamnet/routes`<br>`PATCH/DELETE .../teamnet/routes/{id}` | **Per-route resource** (`network`, `tunnel_id`, `virtual_network_id`). |
| `cloudflare_zero_trust_tunnel_cloudflared_virtual_network` | `POST /accounts/{id}/teamnet/virtual_networks`<br>`PATCH/DELETE .../virtual_networks/{id}` | **Per-vnet resource** (`name`, `comment`, `is_default_network`). |
| `cloudflare_zero_trust_gateway_policy` | `POST/PUT/DELETE /accounts/{id}/gateway/rules` | **Per-rule resource** (`action`, `traffic`, `identity`, `filters = ["l4"]`). |
| `cloudflare_zero_trust_access_application` | `POST/PUT/DELETE /accounts/{id}/access/apps` | **Per-app resource** (`type = "self_hosted"`, `destinations[]` for private routes). |

*Note on Hostname Routes in Terraform*: As of provider v5.25.0, hostname routes configured via `/zerotrust/routes/hostname` are managed via the REST API or Access private application destinations; a separate dedicated `cloudflare_zero_trust_tunnel_cloudflared_hostname_route` resource is pending provider release.

### Go SDK (`github.com/cloudflare/cloudflare-go/v4`)
- `client.ZeroTrust.Devices.Policies.Default.Get / Edit`
- `client.ZeroTrust.Devices.Policies.Custom.New / Get / Edit / Delete / List`
- `client.ZeroTrust.Devices.Settings.Get / Edit`
- `client.ZeroTrust.Networks.Routes.New / Get / Edit / Delete / List`
- `client.ZeroTrust.Networks.VirtualNetworks.New / Get / Edit / Delete / List`
- `client.ZeroTrust.Networks.HostnameRoutes.New / Get / Edit / Delete / List`
- `client.ZeroTrust.Access.Applications.New / Edit / Delete`
- `client.ZeroTrust.Gateway.Rules.New / Edit / Delete`
- `client.ZeroTrust.Organizations.Get / Update`

---

## Modeling references in other operators

### 1. Tailscale Kubernetes Operator
The Tailscale operator exposes cluster workloads and connects clusters to private tailnets. Its routing model centers around the `Connector` custom resource and service-level annotations:

- **`Connector` CRD (`tailscale.com/v1alpha1`)**:
  Represents a deployed Tailscale node acting as a bridge. Key fields:
  ```yaml
  apiVersion: tailscale.com/v1alpha1
  kind: Connector
  metadata:
    name: k8s-subnet-router
  spec:
    subnetRouter:
      advertiseRoutes:
        - "10.244.0.0/16"      # Pod CIDR
        - "10.96.0.0/12"       # Service CIDR
    exitNode: false
    appConnector:
      routes:
        - "192.168.1.0/24"
  ```
- **Annotations Reference**:
  - `tailscale.com/expose: "true"`: Exposes a Kubernetes Service directly on the tailnet.
  - `tailscale.com/hostname: "<name>"`: Assigns a MagicDNS hostname to the service.
  - `tailscale.com/tailnet-fqdn: "<target.fqdn>"`: Egress mapping to tailnet services.
  - `tailscale.com/proxy-group: "<group-name>"`: Ties egress/ingress to a high-availability proxy group.

### 2. StringKe/cloudflare-operator (`networking.cloudflare-operator.io/v1alpha2`)
`StringKe/cloudflare-operator` provides an explicit three-layer architecture for reconciling Cloudflare Zero Trust into Kubernetes:

- **`NetworkRoute` CRD (Cluster-scoped)**:
  Maps directly to `/teamnet/routes`. Spec fields:
  - `network`: Target CIDR string (e.g. `10.0.0.0/8`).
  - `tunnelRef`: `{ kind: "Tunnel" | "ClusterTunnel", name: "<tunnel-name>" }`.
  - `virtualNetworkRef`: `{ name: "<vnet-cr-name>" }` (resolves to Cloudflare Virtual Network ID).
  - `comment`: Descriptive metadata.
- **`VirtualNetwork` CRD (Cluster-scoped)**:
  Maps directly to `/teamnet/virtual_networks`. Spec fields:
  - `name`: Virtual network display name.
  - `comment`: Description.
  - `isDefaultNetwork`: Boolean flag.
- **`DeviceSettingsPolicy` CRD (Cluster-scoped)**:
  Models WARP device split tunneling with automated route aggregation:
  - `splitTunnelMode`: Enum `"exclude" | "include"`.
  - `splitTunnelExclude`: List of `{ address, host, description }`.
  - `splitTunnelInclude`: List of `{ address, host, description }`.
  - `fallbackDomains`: List of `{ suffix, description, dnsServer }`.
  - `autoPopulateFromRoutes`:
    ```yaml
    autoPopulateFromRoutes:
      enabled: true
      labelSelector:
        matchLabels:
          environment: production
      descriptionPrefix: "Auto-populated from NetworkRoute: "
    ```
  *Key Insight for Flareway*: `DeviceSettingsPolicy` demonstrates how an operator can solve the "single-writer" split-tunnel problem by allowing `NetworkRoute` or `HTTPRoute` resources to dynamically populate a unified split-tunnel array via an aggregator controller.

---

## Sources
- Cloudflare One Documentation Index: https://developers.cloudflare.com/cloudflare-one/llms.txt
- Cloudflare Device Profiles: https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/configure/device-profiles/
- Cloudflare Device Client Settings: https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/configure/settings/
- Cloudflare Split Tunnels: https://developers.cloudflare.com/cloudflare-one/connections/connect-devices/warp/configure-warp/route-traffic/split-tunnels/
- Cloudflare Local Domain Fallback: https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/configure/route-traffic/local-domains/
- Cloudflare Account Limits: https://developers.cloudflare.com/cloudflare-one/account-limits/
- Cloudflare Connect Private Hostname: https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/private-net/cloudflared/connect-private-hostname/
- Cloudflare Add Routes: https://developers.cloudflare.com/cloudflare-one/networks/routes/add-routes/
- Cloudflare Virtual Networks: https://developers.cloudflare.com/cloudflare-one/networks/virtual-networks/
- Cloudflare Tunnel Virtual Networks: https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/private-net/cloudflared/tunnel-virtual-networks/
- Cloudflare Access Self-Hosted Private Applications: https://developers.cloudflare.com/cloudflare-one/access-controls/applications/non-http/self-hosted-private-app/
- Cloudflare Access Session Management: https://developers.cloudflare.com/cloudflare-one/access-controls/access-settings/session-management/
- Cloudflare API Reference (Zero Trust): https://developers.cloudflare.com/api/resources/zero_trust/
- Terraform Provider Cloudflare GitHub Repository (v5.25.0 docs): https://github.com/cloudflare/terraform-provider-cloudflare
- Tailscale Kubernetes Operator Documentation: https://tailscale.com/docs/kubernetes-operator
- StringKe/cloudflare-operator Repository: https://github.com/StringKe/cloudflare-operator

---

## Open questions / gaps
1. **Terraform Provider Support for Hostname Routes**: While the REST API endpoint `/accounts/{account_id}/zerotrust/routes/hostname` is live and documented, Terraform provider v5.25.0 does not yet publish a dedicated `cloudflare_zero_trust_tunnel_cloudflared_hostname_route` resource. The operator must manage this either via raw Go SDK calls or via `cloudflare_zero_trust_access_application` destinations.
2. **Dynamic Route Injection Latency in WARP Client**: Split tunnel updates pushed via `PUT /devices/policy/.../include|exclude` can take up to 10 minutes to propagate to connected clients unless the client reconnects. Testing is needed to verify whether private hostname routing (using the static `172.64.128.0/20` range) completely avoids client-side propagation latency for newly created Kubernetes routes.
3. **Gateway API Extension Point for Virtual Networks**: The Gateway API `Gateway` or `GatewayClass` specification has no native field for VRF / Virtual Network IDs. Flareway's orchestrator must decide whether to attach `virtual_network_id` via a custom `CloudflareVirtualNetwork` CRD reference in `spec.infrastructure.parametersRef`, a Gateway annotation (e.g. `flareway.runbear.io/virtual-network`), or a custom PolicyAttachment.
