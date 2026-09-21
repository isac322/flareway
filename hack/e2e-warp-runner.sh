#!/usr/bin/env bash
#
# e2e-warp-runner.sh — bootstrap and clean up a headless Cloudflare One Client
# (WARP) registration for the private-hostname e2e spec on an ephemeral Linux
# runner.
#
# bootstrap:
#   1. installs the cloudflare-warp package (Debian/Ubuntu) when absent,
#   2. resolves the Zero Trust team name from the organization auth_domain and
#      finds the single WARP enrollment Access application,
#   3. creates a per-run Access service token, an app-scoped non_identity
#      enrollment policy bound to that exact token, and a custom device
#      profile selected by identity.service_token_uuid,
#   4. registers the client through the documented MDM parameters
#      (/var/lib/cloudflare-warp/mdm.xml) and connects it,
#   5. verifies the applied profile via the `warp-cli settings` Profile ID.
#
# cleanup deletes the registration, device profile, enrollment policy, and
# service token in reverse order using the IDs recorded in the state file,
# then removes mdm.xml. cleanup is safe to run after a partial bootstrap.
#
# Required environment:
#   FLAREWAY_E2E_CF_API_TOKEN   Cloudflare API token (Access: Service Tokens
#                             Write, Access: Apps and Policies Write,
#                             Zero Trust Write)
#   FLAREWAY_E2E_CF_ACCOUNT_ID  Cloudflare account ID
# Optional:
#   FLAREWAY_E2E_CF_BASE_URL    Cloudflare API base URL override
#   WARP_RUNNER_STATE           state file path
#                             (default ${RUNNER_TEMP:-/tmp}/flareway-warp-runner.env)
#   WARP_RUN_ID                 8-hex run suffix shared with the e2e janitor
#                             naming contract (random when unset)

set -euo pipefail

CF_API_TOKEN="${FLAREWAY_E2E_CF_API_TOKEN:-}"
CF_ACCOUNT_ID="${FLAREWAY_E2E_CF_ACCOUNT_ID:-}"
CF_API_BASE="${FLAREWAY_E2E_CF_BASE_URL:-https://api.cloudflare.com/client/v4}"
STATE_FILE="${WARP_RUNNER_STATE:-${RUNNER_TEMP:-/tmp}/flareway-warp-runner.env}"
MDM_FILE="/var/lib/cloudflare-warp/mdm.xml"

log() { printf 'warp-runner: %s\n' "$*"; }
fail() { printf 'warp-runner: %s\n' "$*" >&2; exit 1; }

require_env() {
  [[ -n "${CF_API_TOKEN}" ]] || fail "FLAREWAY_E2E_CF_API_TOKEN is required"
  [[ -n "${CF_ACCOUNT_ID}" ]] || fail "FLAREWAY_E2E_CF_ACCOUNT_ID is required"
}

# cf_api METHOD PATH [JSON_BODY] prints the raw response body and fails when
# the transport or the Cloudflare success flag fails. Callers must not print
# the response of secret-returning endpoints.
cf_api() {
  local method="$1" path="$2" body="${3:-}"
  local -a args=(
    --silent --show-error --request "${method}"
    --config -
    --header "Accept: application/json"
  )
  if [[ -n "${body}" ]]; then
    args+=(--header "Content-Type: application/json" --data "${body}")
  fi
  local response
  # The API token travels over a stdin config file so it never appears in the
  # curl process arguments.
  if ! response="$(printf 'header = "Authorization: Bearer %s"\n' "${CF_API_TOKEN}" \
      | curl "${args[@]}" "${CF_API_BASE}${path}")"; then
    printf 'warp-runner: cloudflare %s %s transport error\n' "${method}" "${path}" >&2
    return 1
  fi
  if [[ "$(jq -r '.success // false' <<<"${response}" 2>/dev/null)" != "true" ]]; then
    # Report only error codes: remote messages may echo request data.
    printf 'warp-runner: cloudflare %s %s failed (codes: %s)\n' "${method}" "${path}" \
      "$(jq -c '[.errors[]?.code] // empty' <<<"${response}" 2>/dev/null || printf 'unparseable response')" >&2
    return 1
  fi
  printf '%s' "${response}"
}

cf_result() { cf_api "$@" | jq -c '.result'; }

# cf_list_items PATH prints every live item of a paginated list endpoint as
# compact JSON, one per line. Tombstoned objects (deleted_at/deleted set, as
# returned by /devices/registrations?status=all) are excluded.
cf_list_items() {
  local path="$1" cursor="" sep='?' response
  [[ "${path}" == *\?* ]] && sep='&'
  while :; do
    response="$(cf_api GET "${path}${sep}per_page=50${cursor:+&cursor=${cursor}}")"
    jq -c '.result[]? | select((.deleted_at // null) == null and (.deleted // false) == false)' \
      <<<"${response}"
    cursor="$(jq -r '.result_info.cursor // empty' <<<"${response}")"
    [[ -n "${cursor}" ]] || break
  done
}

# cf_http_code PATH prints the HTTP status of a GET without judging success.
cf_http_code() {
  local path="$1"
  printf 'header = "Authorization: Bearer %s"\n' "${CF_API_TOKEN}" \
    | curl --silent --show-error --config - --header "Accept: application/json" \
        --output /dev/null --write-out '%{http_code}' "${CF_API_BASE}${path}"
}

state_set() {
  local key="$1" value="$2" tmp
  touch "${STATE_FILE}"
  chmod 600 "${STATE_FILE}"
  tmp="$(mktemp)"
  grep -v "^${key}=" "${STATE_FILE}" >"${tmp}" 2>/dev/null || true
  printf '%s=%s\n' "${key}" "${value}" >>"${tmp}"
  mv "${tmp}" "${STATE_FILE}"
  chmod 600 "${STATE_FILE}"
}

state_get() {
  local key="$1"
  [[ -f "${STATE_FILE}" ]] || return 0
  sed -n "s/^${key}=//p" "${STATE_FILE}" | tail -1
}

warp_cli() {
  if command -v warp-cli >/dev/null 2>&1 && warp-cli --accept-tos "$@"; then
    return 0
  fi
  sudo warp-cli --accept-tos "$@"
}

install_warp() {
  if command -v warp-cli >/dev/null 2>&1; then
    log "cloudflare-warp already installed"
    return 0
  fi
  local codename
  codename="$(. /etc/os-release && printf '%s' "${VERSION_CODENAME:-}")"
  [[ -n "${codename}" ]] || fail "cannot determine the distro codename for the Cloudflare apt repository"
  log "installing cloudflare-warp (${codename})"
  curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | \
    sudo gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
  printf 'deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ %s main\n' \
    "${codename}" | sudo tee /etc/apt/sources.list.d/cloudflare-client.list >/dev/null
  sudo apt-get update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq cloudflare-warp
  command -v warp-cli >/dev/null 2>&1 || fail "warp-cli missing after cloudflare-warp install"
}

# delete_remote PATH LABEL deletes one remote object. A failed delete is
# tolerated only when an exact GET proves the object absent (404) or
# tombstoned (deleted_at/deleted set). List endpoints are never used for
# absence proof: some are single-page or include tombstones.
delete_remote() {
  local path="$1" label="$2" id="${1##*/}" code body
  if cf_api DELETE "${path}" >/dev/null 2>&1; then
    log "deleted ${label} ${id}"
    return 0
  fi
  code="$(cf_http_code "${path}" 2>/dev/null || true)"
  if [[ "${code}" == "404" ]]; then
    log "${label} ${id} already absent"
    return 0
  fi
  if [[ "${code}" == "200" ]]; then
    body="$(cf_api GET "${path}" 2>/dev/null || true)"
    if [[ "$(jq -r '(.result.deleted_at // .result.deleted // null) != null and (.result.deleted_at // .result.deleted) != false' \
        <<<"${body}" 2>/dev/null)" == "true" ]]; then
      log "${label} ${id} already tombstoned"
      return 0
    fi
  fi
  printf 'warp-runner: %s %s delete failed (verification GET status %s)\n' "${label}" "${id}" "${code:-none}" >&2
  return 1
}

bootstrap() {
  require_env
  command -v jq >/dev/null 2>&1 || fail "jq is required"
  command -v curl >/dev/null 2>&1 || fail "curl is required"
  command -v systemctl >/dev/null 2>&1 || fail "systemd is required to run warp-svc"
  install_warp

  # Refuse to touch a host that already carries a WARP enrollment or an mdm.xml
  # this script did not write.
  if sudo test -f "${MDM_FILE}"; then
    fail "${MDM_FILE} already exists; refusing to overwrite an existing enrollment configuration"
  fi
  if warp_cli registration show >/dev/null 2>&1; then
    fail "this host already has a WARP registration; refusing to re-register"
  fi

  local run_id="${WARP_RUN_ID:-}"
  if [[ -z "${run_id}" ]]; then
    run_id="$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"
  fi
  [[ "${run_id}" =~ ^[0-9a-f]{8}$ ]] || fail "WARP_RUN_ID must be 8 lowercase hex characters, got ${run_id}"

  local org auth_domain team_name
  org="$(cf_result GET "/accounts/${CF_ACCOUNT_ID}/access/organizations")" \
    || fail "cannot read the Zero Trust organization; Terraform must create it"
  auth_domain="$(jq -r '.auth_domain // empty' <<<"${org}")"
  team_name="${auth_domain%.cloudflareaccess.com}"
  [[ -n "${team_name}" && "${team_name}" != "${auth_domain}" ]] \
    || fail "organization auth_domain ${auth_domain:-<empty>} is not a cloudflareaccess.com domain"

  local warp_apps warp_app_id
  warp_apps="$(cf_result GET "/accounts/${CF_ACCOUNT_ID}/access/apps" \
    | jq -c '[.[] | select(.type == "warp")]')" \
    || fail "cannot list Access applications"
  [[ "$(jq 'length' <<<"${warp_apps}")" == "1" ]] \
    || fail "expected exactly one WARP enrollment application, found $(jq 'length' <<<"${warp_apps}"); Terraform must create the type=warp app"
  warp_app_id="$(jq -r '.[0].id' <<<"${warp_apps}")"
  log "team ${team_name}, warp enrollment app ${warp_app_id}, run ${run_id}"

  : >"${STATE_FILE}"
  chmod 600 "${STATE_FILE}"
  state_set RUN_ID "${run_id}"
  state_set WARP_APP_ID "${warp_app_id}"
  state_set TEAM_NAME "${team_name}"

  # Registrations are matched to this run by their bound device profile, not by
  # set difference: a concurrent registration elsewhere in the account must
  # never be adopted or deleted by this run.
  local registrations_path="/accounts/${CF_ACCOUNT_ID}/devices/registrations?status=all&include=policy"

  local token_json token_id client_id client_secret
  token_json="$(cf_result POST "/accounts/${CF_ACCOUNT_ID}/access/service_tokens" \
    "$(jq -cn --arg name "flareway-e2e-${run_id}-warp-token" \
      '{name: $name, duration: "24h"}')")" || fail "service token create failed"
  token_id="$(jq -r '.id' <<<"${token_json}")"
  client_id="$(jq -r '.client_id' <<<"${token_json}")"
  client_secret="$(jq -r '.client_secret' <<<"${token_json}")"
  [[ -n "${token_id}" && "${token_id}" != "null" && -n "${client_secret}" && "${client_secret}" != "null" ]] \
    || fail "service token response lacked id or client_secret"
  state_set TOKEN_ID "${token_id}"
  log "created service token ${token_id}"

  local policy_json policy_id
  policy_json="$(cf_result POST "/accounts/${CF_ACCOUNT_ID}/access/apps/${warp_app_id}/policies" \
    "$(jq -cn --arg name "flareway-e2e-${run_id}-warp-enroll" --arg tid "${token_id}" \
      '{name: $name, decision: "non_identity",
        include: [{service_token: {token_id: $tid}}]}')")" \
    || fail "enrollment policy create failed"
  policy_id="$(jq -r '.id' <<<"${policy_json}")"
  [[ -n "${policy_id}" && "${policy_id}" != "null" ]] || fail "enrollment policy response lacked id"
  state_set POLICY_ID "${policy_id}"
  log "created enrollment policy ${policy_id}"

  # The description carries the janitor's durable creation marker: custom
  # device profiles expose no created_at, so stale sweeps key off this token.
  local profile_json profile_id created_at
  created_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  profile_json="$(cf_result POST "/accounts/${CF_ACCOUNT_ID}/devices/policy" \
    "$(jq -cn --arg name "flareway-e2e-${run_id}-warp-profile" --arg tid "${token_id}" \
      --arg created "flareway-e2e-at=${created_at}" \
      '{name: $name, description: ("Flareway e2e WARP runner profile " + $created),
        match: ("identity.service_token_uuid == \"" + $tid + "\""),
        precedence: 1, enabled: true,
        service_mode_v2: {mode: "warp"},
        switch_locked: true, allow_mode_switch: false, allowed_to_leave: false,
        auto_connect: 0, captive_portal: 0}')")" || fail "device profile create failed"
  profile_id="$(jq -r '.policy_id // .id' <<<"${profile_json}")"
  [[ -n "${profile_id}" && "${profile_id}" != "null" ]] || fail "device profile response lacked policy_id"
  state_set PROFILE_ID "${profile_id}"
  log "created device profile ${profile_id}"

  # Include-mode split tunnel: only the private-hostname synthetic ranges and
  # the e2e internal suffix traverse WARP, so runner traffic is otherwise
  # untouched and a direct query to a public resolver bypasses WARP.
  cf_api PUT "/accounts/${CF_ACCOUNT_ID}/devices/policy/${profile_id}/include" \
    '[{"address":"172.64.128.0/20","description":"flareway e2e synthetic v4"},
      {"address":"2606:4700:0cf1:4000::/64","description":"flareway e2e synthetic v6"},
      {"address":"100.80.0.0/16","description":"flareway e2e synthetic v4 alt"},
      {"host":"flareway.internal","description":"flareway e2e private hostnames"}]' \
    >/dev/null || fail "split-tunnel include list update failed"

  log "writing ${MDM_FILE} and restarting warp-svc"
  sudo mkdir -p "$(dirname "${MDM_FILE}")"
  printf '%s\n' \
    '<?xml version="1.0" encoding="UTF-8"?>' \
    '<dict>' \
    '  <key>organization</key>' \
    "  <string>${team_name}</string>" \
    '  <key>auth_client_id</key>' \
    "  <string>${client_id}</string>" \
    '  <key>auth_client_secret</key>' \
    "  <string>${client_secret}</string>" \
    '</dict>' | sudo tee "${MDM_FILE}" >/dev/null
  sudo chmod 600 "${MDM_FILE}"
  sudo systemctl restart warp-svc
  warp_cli status >/dev/null 2>&1 || true

  # Select only the registration bound to this run's device profile. A
  # registration carries the applied profile under .policy.id (include=policy)
  # or .policy_id; anything else in the account is ignored, and more than one
  # match fails closed.
  local registration_id="" attempt
  local -a matches=()
  for attempt in $(seq 1 60); do
    mapfile -t matches < <(cf_list_items "${registrations_path}" \
      | jq -r --arg pid "${profile_id}" \
        'select((.policy.id // .policy_id // "") == $pid) | .id // empty' || true)
    if ((${#matches[@]} > 0)); then
      break
    fi
    sleep 2
  done
  ((${#matches[@]} > 0)) || fail "no registration bound to profile ${profile_id} appeared within 120s"
  ((${#matches[@]} == 1)) || fail "expected exactly one registration bound to profile ${profile_id}, found ${#matches[@]}"
  registration_id="${matches[0]}"
  state_set REGISTRATION_ID "${registration_id}"
  log "registered as ${registration_id}"

  warp_cli connect || fail "warp-cli connect failed"
  local status=""
  for attempt in $(seq 1 30); do
    status="$(warp_cli status 2>/dev/null || true)"
    if grep -qiw 'connected' <<<"${status}"; then
      break
    fi
    sleep 2
  done
  grep -qiw 'connected' <<<"${status}" || fail "WARP did not reach Connected state: ${status}"

  local applied=""
  for attempt in $(seq 1 60); do
    applied="$(warp_cli settings 2>/dev/null \
      | sed -n 's/.*[Pp]rofile ID[:= ]\{1,\}\([0-9a-fA-F-]\{36\}\).*/\1/p' | head -1 || true)"
    [[ "${applied}" == "${profile_id}" ]] && break
    sleep 2
  done
  [[ "${applied}" == "${profile_id}" ]] \
    || fail "applied profile ${applied:-<none>} does not match expected ${profile_id}"
  log "connected; applied profile ${applied}"
  printf 'warp_device=1\n'
}

cleanup() {
  local rc=0
  if [[ ! -f "${STATE_FILE}" ]]; then
    log "no state file; nothing to clean"
    return 0
  fi

  # Local teardown only runs when this script recorded a run: never wipe a
  # foreign enrollment.
  if command -v warp-cli >/dev/null 2>&1; then
    warp_cli disconnect >/dev/null 2>&1 || true
    warp_cli registration delete >/dev/null 2>&1 || true
  fi
  sudo rm -f "${MDM_FILE}" 2>/dev/null || true

  require_env

  local registration_id profile_id policy_id warp_app_id token_id
  registration_id="$(state_get REGISTRATION_ID)"
  profile_id="$(state_get PROFILE_ID)"
  policy_id="$(state_get POLICY_ID)"
  warp_app_id="$(state_get WARP_APP_ID)"
  token_id="$(state_get TOKEN_ID)"

  local registration_gone=1
  if [[ -n "${registration_id}" ]]; then
    if delete_remote "/accounts/${CF_ACCOUNT_ID}/devices/registrations/${registration_id}" \
      "registration"; then
      registration_gone=0
    else
      rc=1
    fi
  else
    registration_gone=0
  fi
  # The profile is the janitor's ownership link for the registration: keep it
  # while a registration deletion is unconfirmed, but still revoke the
  # enrollment policy and service token so nothing can enroll again.
  if [[ -n "${profile_id}" && "${registration_gone}" == "0" ]]; then
    delete_remote "/accounts/${CF_ACCOUNT_ID}/devices/policy/${profile_id}" \
      "device profile" || rc=1
  elif [[ -n "${profile_id}" ]]; then
    printf 'warp-runner: keeping device profile %s so the janitor can still own registration %s\n' \
      "${profile_id}" "${registration_id}" >&2
  fi
  if [[ -n "${policy_id}" && -n "${warp_app_id}" ]]; then
    delete_remote "/accounts/${CF_ACCOUNT_ID}/access/apps/${warp_app_id}/policies/${policy_id}" \
      "enrollment policy" || rc=1
  fi
  if [[ -n "${token_id}" ]]; then
    delete_remote "/accounts/${CF_ACCOUNT_ID}/access/service_tokens/${token_id}" \
      "service token" || rc=1
  fi

  if ((rc == 0)); then
    rm -f "${STATE_FILE}"
  else
    printf 'warp-runner: cleanup incomplete; stale objects remain under run %s\n' \
      "$(state_get RUN_ID)" >&2
  fi
  return "${rc}"
}

action="${1:-}"
case "${action}" in
  bootstrap)
    trap 'rc=$?; if ((rc != 0)) && [[ -f "${STATE_FILE}" ]]; then log "bootstrap failed; cleaning up partial state"; cleanup || true; fi' EXIT
    bootstrap
    ;;
  cleanup)
    cleanup
    ;;
  *)
    fail "usage: $0 {bootstrap|cleanup}"
    ;;
esac
