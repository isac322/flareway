# Cloudflare Access (Zero Trust) Architecture & API Reference

**Document Version / Date:** 2026-09-12  
**Target:** Cloudflare Access (Zero Trust) — Applications, Policies, Groups, Service Tokens, Identity Providers, Device Posture, JWT Validation, Session Semantics, Tunnel Interplay, and SDK/Terraform Mapping.

---

## Summary (10 bullets max)

1. **Access Application API**: Created at `/accounts/{account_id}/access/apps`. Self-hosted apps configure public hostnames/paths or private network routes; the modern `destinations` array supersedes the deprecated `self_hosted_domains` field (deprecated through late 2025).
2. **AUD Tag Stability**: The Audience (`aud`) tag is a 64-character hex string generated once at application creation. It remains immutable across domain, destination, and policy updates, changing only if the application is deleted and recreated.
3. **Domain & Path Overlap**: Cloudflare Edge enforces exact/more-specific path precedence (`example.com/admin` takes precedence over `example.com`), and no rules are inherited from parent paths to explicit child apps.
4. **Policy Engine & Decisions**: Reusable policies exist at `/accounts/{account_id}/access/policies` with actions `bypass`, `non_identity` (Service Auth), `allow`, and `deny` (Block). Bypass and Non-Identity are evaluated first, followed by Allow and Deny in order of precedence; first matching decision terminates evaluation.
5. **Rule Typing & Logic**: An Access policy evaluates candidate pools via `include` (OR logic), restricts via `require` (AND logic), and carves exceptions via `exclude` (AND-NOT logic). Standalone `warp` and `gateway` checks are implemented via `device_posture` rules referencing client posture check definitions.
6. **Service Tokens**: Generated at `/access/service_tokens`; `client_id` and `client_secret` are returned only on creation. Secrets are rotated via `/rotate` (with optional `previous_client_secret_expires_at` grace periods) or extended via `/refresh`. Presented via headers `CF-Access-Client-Id` and `CF-Access-Client-Secret`.
7. **Identity Providers**: Account-level integrations (`/access/identity_providers`) configure OIDC, SAML, Google Workspace, Azure AD, Okta, and OTP. Policy rules reference IdP configurations explicitly by ID (`identity_provider_id`).
8. **JWT & Cryptographic Verification**: Signed with RS256 using account keys at `https://<team-name>.cloudflareaccess.com/cdn-cgi/access/certs` (rotated every 6 weeks with a 7-day grace period). Claims include `aud`, `email`, `sub`, `iss`, `iat`, `exp`, `identity_nonce`, and `common_name`.
9. **Revocation Latency Caveat**: Cloudflare Edge cookie and token revocation propagates globally within 20–30 seconds. However, origins or `cloudflared` connectors that validate JWTs statelessly without calling edge revocation lists will accept revoked tokens until cryptographic expiration (`exp`).
10. **Flareway Ownership & Rate Limits**: Applications support account-level tags, but every tag must exist before assignment and tag names are limited to 35 characters. Flareway therefore creates a shared `flareway-managed` tag plus bounded SHA-256-derived owner/bypass tags. Policies, groups, and service tokens only support `name`, requiring prefixed naming conventions. The standard Cloudflare API rate limit is 1,200 requests per 5 minutes.

---

## Applications

### Application Endpoint & Schema (`type: self_hosted`)
- **Primary Endpoint:** `POST /accounts/{account_id}/access/apps` (mutually exclusive with zone-scoped `/zones/{zone_id}/access/apps`).
- **Resource Type:** `self_hosted`.

| Field Name | Type | Description |
|---|---|---|
| `name` | `string` | Display name of the application. |
| `type` | `string` | Application type: `self_hosted` (also `saas`, `ssh`, `vnc`, `app_launcher`, `warp`, `biso`, `bookmark`, `infrastructure`, `dash_sso`, `rdp`, `mcp`, `mcp_portal`, `proxy_endpoint`). |
| `domain` | `string` | Primary hostname/path protected by Access (e.g., `app.example.com/admin`). |
| `self_hosted_domains` | `array of string` | **Deprecated** list of public domains. Superseded by `destinations`. |
| `destinations` | `array of object` | Modern destination array supporting public URIs, private CIDRs, and Worker routes. |
| `session_duration` | `string` | Session lifetime (e.g. `24h`, `30m`). Defaults to organization default. |
| `allowed_idps` | `array of string` | Identity provider UUIDs allowed for login. Defaults to all configured IdPs. |
| `auto_redirect_to_identity` | `boolean` | Skips IdP picker if exactly one IdP is listed in `allowed_idps`. |
| `app_launcher_visible` | `boolean` | Displays the application tile in the Zero Trust App Launcher. |
| `enable_binding_cookie` | `boolean` | Binds the user session cookie to the client IP/device to mitigate cookie hijacking. |
| `http_only_cookie_attribute` | `boolean` | Enables `HttpOnly` flag on Access session cookies. |
| `same_site_cookie_attribute` | `string` | Sets `SameSite` cookie attribute (`lax`, `strict`, `none`). |
| `path_cookie_attribute` | `boolean` | Restricts the Access session cookie path to the application's path instead of `/`. |
| `service_auth_401_redirect` | `boolean` | Returns HTTP `401 Unauthorized` instead of `302 Redirect` to IdP for failed service auth / API calls. |
| `skip_interstitial` | `boolean` | Skips the Access landing page when authenticating via WARP. |
| `options_preflight_bypass` | `boolean` | Bypasses Access policies for unauthenticated HTTP `OPTIONS` CORS preflight requests. |
| `cors_headers` | `object` | Configures allowed headers, methods, origins, credentials, and max-age for CORS. |
| `custom_deny_message` | `string` | Custom error message shown to blocked users on the Access block page. |
| `custom_deny_url` | `string` | Redirect URL when a user fails an identity policy check. |
| `custom_non_identity_deny_url`| `string` | Redirect URL when a user fails a non-identity policy check (e.g. device posture/mTLS). |
| `tags` | `array of string` | Metadata tags attached to the application. Ideal for Flareway ownership labeling. |
| `allow_authenticate_via_warp` | `boolean` | Overrides organization default to allow authentication via WARP client session. |
| `policies` | `array of object` | Application policies. Accepts reusable policy references `[{"id": "...", "precedence": 1}]`. |
| `custom_pages` | `array of string` | UUIDs of custom HTML block pages hosted in Cloudflare One. |
| `read_service_tokens_from_header` | `string` | Custom header name containing service token credentials as an alternative to default headers. |
| `skip_app_launcher_login_page` | `boolean` | Bypasses launcher login screen if session is already active. |

### Destinations Specification (`destinations[]`)
The `destinations` field replaces `self_hosted_domains` and allows heterogeneous target definitions:
1. **Public Destination:**
   ```json
   {
     "type": "public",
     "uri": "app.example.com/api/*"
   }
   ```
2. **Private Destination:**
   ```json
   {
     "type": "private",
     "hostname": "internal-service.local",
     "cidr": "10.244.0.0/16",
     "l4_protocol": "tcp",
     "port_range": "80-443",
     "vnet_id": "a91845bb-c5da-4c07-ba21-127e9ff0f5e1"
   }
   ```
3. **Worker Destination:**
   `{"type": "worker", "worker_id": "uuid"}` or `{"type": "all_workers"}`.
4. **MCP Portal Destination:**
   `{"type": "via_mcp_server_portal", "mcp_server_id": "uuid"}`.

### AUD Tag Stability & Lifecycle
- **Field:** `aud: string` (64-character hex string returned in API responses).
- **Stability:** Cloudflare guarantees the AUD tag is immutable for the lifetime of the application. Updating the application's domain, destinations, or policies does **not** alter the AUD tag.
- **Multiple Destinations:** When an application defines multiple public or private destinations, every destination shares the exact same application AUD tag.
- **Recreation:** The AUD tag changes only if the application object is deleted and recreated.

### Domain & Path Overlap Rules
- **Specificity Precedence:** When overlapping applications exist (e.g., `example.com` and `example.com/admin`), the most specific path match wins. A request to `example.com/admin/settings` matches the `example.com/admin` application.
- **Isolation / No Inheritance:** Child applications do **not** inherit policies from parent applications. If `example.com` allows "All Employees" and `example.com/admin` allows only "Admins", requests to `example.com/admin` evaluate only `example.com/admin` policies.
- **Wildcard Syntax:**
  - Subdomains: `*.example.com` matches single-level subdomains (`app.example.com`), but not apex (`example.com`) or multi-level (`a.b.example.com`).
  - Paths: `example.com/api/*` matches any path segment under `/api/`.
  - Limitation: At most one `*` wildcard between dots in subdomains or slashes in paths. Ports, query parameters (`?query=1`), and hash fragments (`#anchor`) are stripped and unsupported.

---

## Policies

### Policy Endpoints & Architecture
- **Reusable Policies Endpoint:** `POST /accounts/{account_id}/access/policies`
- **Application-Scoped (Legacy) Policies:** `POST /accounts/{account_id}/access/apps/{app_id}/policies`
- **Migration:** Legacy policies can be migrated via `PUT /accounts/{account_id}/access/apps/{app_id}/policies/{policy_id}/make_reusable`.
- **Attachment:** Reusable policies are attached to an application via the application payload `policies: [{"id": "<policy_uuid>", "precedence": 1}]`. Updating a reusable policy updates all attached applications simultaneously.

### Policy Fields
| Field Name | Type | Description |
|---|---|---|
| `name` | `string` | Policy name. |
| `decision` | `string` | Action: `allow`, `deny`, `non_identity` (Service Auth), `bypass`. |
| `include` | `array of object` | Criteria that identify the candidate pool (evaluated with **OR**). At least one required. |
| `require` | `array of object` | Enforcing criteria that candidates must satisfy (evaluated with **AND**). |
| `exclude` | `array of object` | Exception criteria that disqualify candidates (evaluated with **AND NOT**). |
| `precedence` | `number` | Numerical order of evaluation. |
| `session_duration` | `string` | Override session duration for users matching this specific policy. |
| `purpose_justification_required` | `boolean` | Prompts user to enter a business justification before granting access. |
| `purpose_justification_prompt` | `string` | Prompt text displayed for purpose justification. |
| `approval_required` | `boolean` | Requires manual or multi-party approval before granting access. |
| `approval_groups` | `array of object` | Approver group configuration (`{"email_list": [...], "approvals_needed": 1}`). |
| `isolation_required` | `boolean` | Enforces Browser Isolation (RBI) for sessions matching this policy. |
| `connection_rules` | `object` | Infrastructure settings (e.g. allowed SSH usernames). |

### Policy Decision & Ordering Semantics
Cloudflare Access evaluates policies in two strict phases:
1. **Phase 1: Non-Identity & Bypass:**
   - Evaluated first, from lowest precedence number to highest.
   - If a request matches a `bypass` policy, Access authentication is completely disabled for the request.
   - If a request matches a `non_identity` policy (Service Tokens, mTLS), service credentials are validated.
2. **Phase 2: Allow & Deny (Block):**
   - Evaluated next, in strict order of precedence.
   - The first policy whose rules evaluate to `true` terminates evaluation.
   - If an `allow` policy matches, access is granted.
   - If a `deny` policy matches, access is rejected immediately (subsequent allow policies are ignored).
   - If no policy matches, access is denied by default.

### Complete Rule Types & Exact JSON Shapes

| Rule Type Selector | JSON Schema / Shape | Description |
|---|---|---|
| `email` | `{"email": {"email": "user@example.com"}}` | Matches specific user email. |
| `email_domain` | `{"email_domain": {"domain": "example.com"}}` | Matches email domain suffix. |
| `email_list` | `{"email_list": {"id": "<list_uuid>"}}` | Matches emails in a Cloudflare Zero Trust List. |
| `everyone` | `{"everyone": {}}` | Matches all users/requests unconditionally. |
| `ip` | `{"ip": {"ip": "198.51.100.0/24"}}` | Matches client IPv4/IPv6 address or CIDR block. |
| `ip_list` | `{"ip_list": {"id": "<list_uuid>"}}` | Matches client IP against a Cloudflare IP List. |
| `certificate` | `{"certificate": {}}` | Matches any valid client certificate (mTLS). |
| `common_name` | `{"common_name": {"common_name": "device.internal"}}` | Matches a specific Common Name in client mTLS certificate. |
| `group` | `{"group": {"id": "<group_uuid>"}}` | Matches membership in an Access Group. |
| `azureAD` | `{"azureAD": {"id": "<entra_group_id>", "identity_provider_id": "<idp_uuid>"}}` | Matches Microsoft Entra ID group membership. |
| `github-organization`| `{"github-organization": {"name": "org-name", "identity_provider_id": "<idp_uuid>"}}` | Matches GitHub organization membership. |
| `gsuite` | `{"gsuite": {"email": "group@company.com", "identity_provider_id": "<idp_uuid>"}}` | Matches Google Workspace group email. |
| `okta` | `{"okta": {"name": "okta-group", "identity_provider_id": "<idp_uuid>"}}` | Matches Okta group name. |
| `saml` | `{"saml": {"attribute_name": "role", "attribute_value": "eng", "identity_provider_id": "<idp_uuid>"}}` | Matches arbitrary SAML attribute claim. |
| `oidc` | `{"oidc": {"claim_name": "groups", "claim_value": "admin", "identity_provider_id": "<idp_uuid>"}}` | Matches arbitrary OIDC ID token claim. |
| `service_token` | `{"service_token": {"token_id": "<service_token_uuid>"}}` | Matches a specific Access Service Token. |
| `any_valid_service_token` | `{"any_valid_service_token": {}}` | Matches any valid Service Token in the account. |
| `external_evaluation`| `{"external_evaluation": {"evaluate_url": "https://api.internal/eval", "keys_url": "https://api.internal/keys"}}` | Delegates decision to an external webhook/Worker. |
| `geo` | `{"geo": {"country_code": "US"}}` | Matches two-letter ISO 3166-1 alpha-2 country code. |
| `auth_method` | `{"auth_method": {"auth_method": "hwk"}}` | Enforces MFA AMR method (e.g. `hwk`, `fido`, `otp`). |
| `device_posture` | `{"device_posture": {"integration_uid": "<posture_check_uuid>"}}` | Enforces a successful device posture check. |
| `login_method` | `{"login_method": {"id": "<idp_uuid>"}}` | Requires login through a specific Identity Provider. |
| `auth_context` | `{"auth_context": {"id": "<id>", "ac_id": "<ac_id>", "identity_provider_id": "<idp_uuid>"}}` | Matches Microsoft Entra Conditional Access Context. |
| `linked_app_token` | `{"linked_app_token": {"app_uid": "<saas_app_uuid>"}}` | Validates OAuth tokens issued by linked Access SaaS app. |
| `user_risk_score` | `{"user_risk_score": {"user_risk_score": ["low", "medium"]}}` | Matches CrowdStrike/Cloudflare user risk levels. |
| `cloudflare_account_member` | `{"cloudflare_account_member": {}}` | Matches members of the host Cloudflare account. |

*Note on WARP / Gateway:* Cloudflare Access does not expose raw `{"warp": {}}` rules in the policy API. WARP client connectivity and Gateway enforcement are modeled exclusively as `device_posture` rules referencing an enabled posture check of type `warp` or `gateway`.

---

## Groups

### Group Endpoints & Nesting
- **Endpoint:** `POST /accounts/{account_id}/access/groups`
- **Schema:**
  ```json
  {
    "name": "Engineering-Staff",
    "include": [
      {"gsuite": {"email": "eng@company.com", "identity_provider_id": "4b684c98-..."}}
    ],
    "require": [
      {"device_posture": {"integration_uid": "7c82a1d2-..."}}
    ],
    "exclude": [
      {"geo": {"country_code": "RU"}}
    ]
  }
  ```
- **Nesting:** Groups can be nested by placing a `group` rule inside an `include`, `require`, or `exclude` array:
  ```json
  {"group": {"id": "nested-group-uuid"}}
  ```
- **Evaluation Semantics:** Groups encapsulate identical Boolean logic (`include` = OR, `require` = AND, `exclude` = AND NOT). Using groups enables DRY policy attachments across multiple applications.

---

## Service Tokens

### Lifecycle & Endpoints
- **Creation Endpoint:** `POST /accounts/{account_id}/access/service_tokens`
  - Body:
    ```json
    {
      "name": "flareway-controller-token",
      "duration": "8760h"
    }
    ```
  - Response: Returns `client_id` (e.g. `88bf3b6d86161464f6509f7219099e57.access`) and `client_secret` (64-char hex string) **exactly once**. The secret cannot be retrieved again.
  - Duration formats: `300ms`, `2h45m`, `8760h` (default 1 year), or `forever`.
- **Secret Rotation Endpoint:** `POST /accounts/{account_id}/access/service_tokens/{id}/rotate`
  - Generates a new `client_secret`.
  - Body parameter `previous_client_secret_expires_at: "<ISO-8601>"` allows configuring a grace period during which the old secret remains valid while clients transition.
- **Expiration Refresh Endpoint:** `POST /accounts/{account_id}/access/service_tokens/{id}/refresh`
  - Extends `expires_at` based on `duration` without changing the existing `client_secret`.

### Client Presentation & App Interaction
- **HTTP Headers:** Clients authenticate by presenting:
  - `CF-Access-Client-Id: <client_id>`
  - `CF-Access-Client-Secret: <client_secret>`
- **Custom Header Override:** An application can set `read_service_tokens_from_header: "X-Custom-Token"` to parse credentials from a single composite header.
- **Handling Rejection (`service_auth_401_redirect`):** By default, unauthenticated automated requests receive a 302 redirect to the HTML login portal. Setting `service_auth_401_redirect: true` on the application forces Access to emit HTTP `401 Unauthorized`, allowing REST/gRPC clients to fail immediately without following HTML redirects.

---

## Identity Providers

### Supported Providers & Account Scoping
- **Endpoint:** `POST /accounts/{account_id}/access/identity_providers`
- **Scope:** Identity Providers are account-level resources. Once defined, they are shared across all Access applications in the account.
- **Supported Provider Types:**
  - Corporate: `azureAD` (Microsoft Entra ID), `okta`, `google-apps` (Google Workspace), `pingfederate`, `centrify`, `jumpcloud`.
  - Protocols: `oidc` (Generic OIDC), `saml` (Generic SAML 2.0).
  - Social / Developer: `github`, `google`, `linkedin`, `facebook`.
  - Built-in: `onetimepin` (Email OTP), `cloudflare` (Cloudflare dashboard auth).
- **Configuration Schema:**
  - Stored in the `config` object (e.g., `client_id`, `client_secret`, `directory_id`, `issuer_url`, `email_attribute_name`).
  - SCIM provisioning settings stored in `scim_config` (supports automated group and user synchronization).
- **Referencing in Policies:** Policy rules reference the IdP's assigned UUID via the `identity_provider_id` field (e.g., `{"gsuite": {"email": "...", "identity_provider_id": "<idp_uuid>"}}`).

---

## Device Posture

### Rule Types & API
- **Endpoint:** `POST /accounts/{account_id}/devices/posture`
- **Supported Posture Check Types:**
  - Client-based (WARP): `file`, `application`, `serial_number`, `os_version`, `domain_joined`, `firewall`, `disk_encryption`, `client_certificate`, `warp`, `gateway`, `unique_client_id`, `antivirus`.
  - Service-to-Service Integrations: `intune`, `crowdstrike_s2s`, `sentinelone_s2s`, `kolide`, `tanium_s2s`, `uptycs`, `workspace_one`.

### Rule Payload Schema
```json
{
  "name": "Enforce Corporate Mac OS & WARP",
  "type": "os_version",
  "schedule": "1h",
  "expiration": "24h",
  "match": [
    {"platform": "mac"}
  ],
  "input": {
    "operator": ">=",
    "version": "14.5.0"
  }
}
```

### Policy Enforcement Semantics
- **Reference:** Embedded into policy rules via `{"device_posture": {"integration_uid": "<posture_check_uuid>"}}`.
- **Evaluation with Groups:** When configured in an Access Policy:
  ```json
  {
    "decision": "allow",
    "include": [{"group": {"id": "<engineers_group_uuid>"}}],
    "require": [{"device_posture": {"integration_uid": "<warp_active_uuid>"}}]
  }
  ```
  The user must satisfy both conditions: they must be a member of the Engineers group **AND** their device must have successfully passed the WARP posture evaluation within its valid `expiration` window.

---

## JWT and Sessions

### Claims Structure (`Cf-Access-Jwt-Assertion`)
When Cloudflare Edge forwards an authenticated request to the origin, it attaches the JWT in the `Cf-Access-Jwt-Assertion` header (and optionally `CF_Authorization` cookie for browsers).

```json
{
  "aud": [
    "4714c1358e65fe4b408ad6d432a5f878f08194bdb4752441fd56faefa9b2b6f2"
  ],
  "email": "developer@company.com",
  "iss": "https://myteam.cloudflareaccess.com",
  "iat": 1726149600,
  "nbf": 1726149600,
  "exp": 1726236000,
  "sub": "7335d417-61da-459d-899c-0a01c76a2f94",
  "identity_nonce": "6ei69kawdKZMiAPF",
  "country": "US",
  "type": "app",
  "common_name": "88bf3b6d86161464f6509f7219099e57.access"
}
```

### JWKS Endpoint & Key Rotation
- **Certificates URL:** `https://<team-name>.cloudflareaccess.com/cdn-cgi/access/certs`
- **Key Format:** Returns standard RFC 7517 JWKS (`keys`), current PEM (`public_cert`), and all valid PEMs (`public_certs`).
- **Rotation Cadence:** Cloudflare automatically rotates signing keys every **6 weeks**.
- **Grace Period:** Rotated keys remain valid in `public_certs` for **7 days** following rotation to prevent edge propagation drops.
- **Manual Rotation:** Can be triggered immediately via `POST /accounts/{account_id}/access/keys/rotate`.

### Organization Settings & Team Domain API
- **Endpoint:** `GET /accounts/{account_id}/access/organizations`
- **Key Response Fields:**
  - `auth_domain`: The canonical team domain (e.g. `myteam.cloudflareaccess.com`).
  - `session_duration`: Default global session duration across applications.
  - `warp_auth_session_duration`: Session duration when authenticating via WARP client.
  - `is_ui_read_only`: Locks dashboard changes to enforce IaC/API-only control.
  - `deny_unmatched_requests`: Global Zero Trust toggle requiring Access protection on all subdomains.

### Session Hierarchies & Revocation Latency
1. **Session Tiers:**
   - **Global Session:** Tracks primary IdP authentication across all applications.
   - **Application Session:** Enforces per-application timeouts defined in `session_duration`.
   - **WARP Session:** Device client session governing overlay access.
2. **Revocation Endpoints:**
   - User revocation: `POST /accounts/{account_id}/access/organizations/revoke_user`
   - App token revocation: `POST /accounts/{account_id}/access/apps/{app_id}/revoke_tokens`
3. **Revocation Latency Caveat:**
   - **At Cloudflare Edge:** Cookies are revoked instantly and global edge PoP caches drop the token in **20–30 seconds**.
   - **At Origin / Cloudflared:** If an origin or `cloudflared` validates the JWT statelessly (verifying RS256 signature and `exp` timestamp without querying Cloudflare's edge revocation endpoint), **it will continue to trust a revoked token until its `exp` timestamp elapses**. For immediate revocation enforcement, session durations should be kept short (e.g., 15m to 1h).

---

## Access + Tunnel Interplay

### Public Applications vs Private Destinations
Cloudflare Tunnel connects private infrastructure to Cloudflare Edge. Its interaction with Access depends on application visibility:

```
[Public User / Browser]
        │ (Public HTTPS)
        ▼
[Cloudflare Edge: Access Application (Public)]
  - Evaluates IdP / mTLS / Policies
  - Issues Cf-Access-Jwt-Assertion
        │ (Argo Tunnel / QUIC)
        ▼
[cloudflared Connector]
  - (Optional) originRequest.access validates JWT & audTag
        ▼
[Kubernetes Service / Pod]
```

```
[Corporate User / WARP Client]
        │ (WireGuard / UDP)
        ▼
[Cloudflare Edge: Access Application (Private Destination)]
  - Evaluates Private IP/CIDR + Posture + Policies
        │ (VNet / Private Tunnel)
        ▼
[cloudflared Connector (routing CIDR)]
        ▼
[Internal Service / RFC1918 IP]
```

### "Protect with Access" Architecture
- **Decoupled APIs:** In the Cloudflare dashboard, the "Protect with Access" checkbox on a tunnel route is a UI wizard shortcut. In the underlying API, the Access Application (`/access/apps`) and Cloudflare Tunnel Ingress configuration (`/tunnels/{id}/configurations`) are separate resources.
- **cloudflared Ingress JWT Enforcement:** A tunnel's ingress rule can configure local JWT verification:
  ```yaml
  ingress:
    - hostname: internal.example.com
      service: http://localhost:8080
      originRequest:
        access:
          required: true
          teamName: myteam
          audTag:
            - 4714c1358e65fe4b408ad6d432a5f878f08194bdb4752441fd56faefa9b2b6f2
  ```
- **Architectural Recommendation:** Because an edge misconfiguration or direct origin network path could bypass Access, Cloudflare strongly advises validating the `Cf-Access-Jwt-Assertion` header at the origin (or in Envoy / in-pod proxy) against the JWKS endpoint and expected `aud`.

---

## Ownership Metadata & Rate Limits

### Object Metadata Support
To prevent conflicting updates between human administrators and Flareway, resources should carry ownership markers:

| Resource Type | Metadata Support | Flareway Strategy |
|---|---|---|
| **Access Application** | pre-created account tag names, maximum 35 characters | Flareway ensures `flareway-managed`, `flareway-owner-<digest>`, and child-only `flareway-bypass-<digest>` before application writes; user tags remain explicit external references. |
| **Access Policy** | **None** (only `name`) | Prefix name: `flareway-[route-name]-[policy-name]`. |
| **Access Group** | **None** (only `name`) | Prefix name: `flareway-[group-name]`. |
| **Service Token** | **None** (only `name`) | Prefix name: `flareway-[token-name]`. |
| **Device Posture Rule**| `description: string` | Use description: `Managed by Flareway Kubernetes Operator`. |

### Cloudflare API Rate Limits
- **Standard Quota:** Cloudflare API v4 applies a global limit of **1,200 requests per 5-minute rolling window** per user/API token.
- **Controller Impact:** Because reconciling large Gateway API routes could exhaust this rate limit, Flareway should implement client-side rate limiting, request batching, and cache API responses (such as organization settings and IdP lists).

---

## SDK / Terraform Type Map

### Go SDK (`github.com/cloudflare/cloudflare-go` v4 / modern SDK)
| Cloudflare Access Entity | Go SDK Service | Go SDK Parameter / Type |
|---|---|---|
| Application | `client.ZeroTrust.Access.Applications` | `zero_trust.AccessApplicationNewParams`, `zero_trust.AccessApplication` |
| Policy | `client.ZeroTrust.Access.Policies` | `zero_trust.AccessPolicyNewParams`, `zero_trust.AccessPolicy` |
| Group | `client.ZeroTrust.Access.Groups` | `zero_trust.AccessGroupNewParams`, `zero_trust.AccessGroup` |
| Service Token | `client.ZeroTrust.Access.ServiceTokens`| `zero_trust.AccessServiceTokenNewParams`, `zero_trust.AccessServiceTokenRotateParams`, `zero_trust.AccessServiceTokenRefreshParams` |
| Identity Provider | `client.ZeroTrust.Access.IdentityProviders`| `zero_trust.AccessIdentityProviderNewParams`, `zero_trust.AccessIdentityProvider` |
| Device Posture | `client.ZeroTrust.Devices.Posture` | `zero_trust.DevicePostureRuleNewParams`, `zero_trust.DevicePostureRule` |
| Organization | `client.ZeroTrust.Organizations` | `zero_trust.OrganizationUpdateParams`, `zero_trust.Organization` |

### Terraform Provider v5 (`cloudflare` provider >= v5.0)
| Resource Concept | Terraform Provider v5 Resource Name |
|---|---|
| Access Application | `cloudflare_zero_trust_access_application` |
| Access Policy | `cloudflare_zero_trust_access_policy` |
| Access Group | `cloudflare_zero_trust_access_group` |
| Service Token | `cloudflare_zero_trust_access_service_token` |
| Identity Provider | `cloudflare_zero_trust_access_identity_provider` |
| Device Posture Rule | `cloudflare_zero_trust_device_posture_rule` |
| Zero Trust Organization | `cloudflare_zero_trust_organization` |

---

## Sources

- [Cloudflare Zero Trust Documentation Index](https://developers.cloudflare.com/cloudflare-one/llms.txt)
- [Cloudflare Access API v4 Reference — Applications](https://developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/applications/)
- [Cloudflare Access API v4 Reference — Policies](https://developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/policies/)
- [Cloudflare Access API v4 Reference — Service Tokens](https://developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/service_tokens/)
- [Cloudflare Access API v4 Reference — Organizations](https://developers.cloudflare.com/api/resources/zero_trust/subresources/organizations/)
- [Cloudflare One — Self-Hosted Applications](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/self-hosted-public-app/)
- [Cloudflare One — Application Paths & Precedence](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/app-paths/)
- [Cloudflare One — JWT Validation & JWKS Endpoint](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/)
- [Cloudflare One — Application Token Claims & Payloads](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/application-token/)
- [Cloudflare One — Session Management & Revocation](https://developers.cloudflare.com/cloudflare-one/access-controls/access-settings/session-management/)
- [Cloudflare One — Device Posture Checks](https://developers.cloudflare.com/cloudflare-one/reusable-components/posture-checks/)
- [Cloudflare Tunnel — Origin Request Parameters & Access Validation](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/configure-tunnels/origin-parameters/)
- [Cloudflare Terraform Provider v5 Overview](https://developers.cloudflare.com/terraform/)

---

## Open questions / gaps

1. **Maximum Reusable Policy Attachment Limit:** The Cloudflare API does not publicly document a hard ceiling on the number of reusable policies attachable to a single Access application. Accounts typically test up to several dozen policies; exact Enterprise limits require verification in live tenants.
2. **Concurrent Policy Re-Ordering Atomicity:** When attaching multiple reusable policies with precedence via `PUT /access/apps/{id}`, the API updates the array atomically. However, concurrent updates across separate controllers without resource versions may experience race conditions.
3. **Real-Time Edge Revocation Webhooks:** Cloudflare does not currently provide a real-time webhook or gRPC stream pushing edge revocation events directly to `cloudflared` or origin proxies. Consequently, stateless JWT validators remain vulnerable to window-of-exposure attacks unless session durations are bounded or validation queries an external state store.
4. **CORS Preflight Bypass vs JWT Header Stripping:** When `options_preflight_bypass` is enabled on an Access application, Edge passes HTTP `OPTIONS` unauthenticated. Downstream origin proxies must ensure that unauthenticated `OPTIONS` requests do not fail an internal mandatory-JWT filter.
