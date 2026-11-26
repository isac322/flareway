---
permissions:
  contents: read
  issues: read
  pull-requests: read
  id-token: write
engine:
  id: codex
  model: gpt-6.2-sol
  auth:
    type: github-oidc
    audience: https://cpa-gw.bhyoo.com
  config: |
    project_doc_max_bytes = 0
  env:
    OPENAI_BASE_URL: https://cpa-gw.bhyoo.com/v1
    AWF_AUTH_TYPE: api-key
    OPENAI_API_KEY: "${{ steps.cpa_oidc.outputs.token || 'oidc-bootstrap' }}"
    CODEX_API_KEY: "${{ steps.cpa_oidc.outputs.token || 'oidc-bootstrap' }}"
pre-steps:
  - name: Mint short-lived CPA gateway token via GitHub OIDC
    id: cpa_oidc
    run: |
      set -euo pipefail
      if [ -z "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ] || [ -z "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" ]; then
        echo "::error::[cpa-oidc] stage=github-oidc missing OIDC request env"
        exit 1
      fi
      HDR="$(mktemp "${RUNNER_TEMP:-/tmp}/cpa-oidc-hdr.XXXXXX")"
      BODY="$(mktemp "${RUNNER_TEMP:-/tmp}/cpa-oidc-body.XXXXXX")"
      trap 'rm -f "$HDR" "$BODY"' EXIT

      case "${ACTIONS_ID_TOKEN_REQUEST_URL}" in
        *\?*) SEP="&" ;;
        *) SEP="?" ;;
      esac
      HTTP_CODE="$(curl -sS -D "$HDR" -o "$BODY" -w '%{http_code}' \
        -H "Authorization: Bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
        "${ACTIONS_ID_TOKEN_REQUEST_URL}${SEP}audience=https%3A%2F%2Fcpa-gw.bhyoo.com")"
      if [ "$HTTP_CODE" != "200" ]; then
        MSG="$(jq -r '(.message // .error // empty) | tostring' "$BODY" 2>/dev/null | tr '\r\n' '  ' | head -c 160 || true)"
        echo "::error::[cpa-oidc] stage=github-oidc http=${HTTP_CODE} message=${MSG}"
        exit 1
      fi
      JWT="$(jq -r '.value // empty' "$BODY")"
      test -n "$JWT"
      echo "::add-mask::${JWT}"

      HTTP_CODE="$(curl -sS -D "$HDR" -o "$BODY" -w '%{http_code}' -X POST "https://cpa-gw.bhyoo.com/oidc/v1/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -H "Accept: application/json" \
        --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
        --data-urlencode "subject_token_type=urn:ietf:params:oauth:token-type:jwt" \
        --data-urlencode "subject_token=${JWT}")"
      if [ "$HTTP_CODE" != "200" ]; then
        hdr() { awk -v k="$1" 'tolower($0) ~ "^" k ":[ \t]*" {sub(/^[^:]*:[ \t]*/, ""); sub(/\r$/, ""); print; exit}' "$HDR" 2>/dev/null || true; }
        CT="$(hdr content-type)"
        SRV="$(hdr server)"
        CF_RAY="$(hdr cf-ray)"
        CF_MIT="$(hdr cf-mitigated)"
        ERR="$(jq -r '(.error // empty) | tostring' "$BODY" 2>/dev/null || true)"
        if [ -z "$ERR" ]; then
          ERR="$(tr '\r\n' '  ' < "$BODY" | grep -oi '<title[^>]*>[^<]*</title>' | head -n 1 | sed 's/<[^>]*>//g' | head -c 80 || true)"
        fi
        echo "::error::[cpa-oidc] stage=cpa-gw http=${HTTP_CODE} content_type=${CT} server=${SRV} cf_ray=${CF_RAY} cf_mitigated=${CF_MIT} error=${ERR}"
        exit 1
      fi
      TOKEN="$(jq -r '.access_token // empty' "$BODY")"
      test -n "$TOKEN"
      echo "::add-mask::${TOKEN}"
      echo "token=${TOKEN}" >> "$GITHUB_OUTPUT"
safe-outputs:
  threat-detection:
    steps:
      - name: Mint short-lived CPA gateway token via GitHub OIDC
        id: cpa_oidc
        if: steps.detection_guard.outputs.run_detection == 'true'
        run: |
          set -euo pipefail
          if [ -z "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ] || [ -z "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" ]; then
            echo "::error::[cpa-oidc] stage=github-oidc missing OIDC request env"
            exit 1
          fi
          HDR="$(mktemp "${RUNNER_TEMP:-/tmp}/cpa-oidc-hdr.XXXXXX")"
          BODY="$(mktemp "${RUNNER_TEMP:-/tmp}/cpa-oidc-body.XXXXXX")"
          trap 'rm -f "$HDR" "$BODY"' EXIT

          case "${ACTIONS_ID_TOKEN_REQUEST_URL}" in
            *\?*) SEP="&" ;;
            *) SEP="?" ;;
          esac
          HTTP_CODE="$(curl -sS -D "$HDR" -o "$BODY" -w '%{http_code}' \
            -H "Authorization: Bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
            "${ACTIONS_ID_TOKEN_REQUEST_URL}${SEP}audience=https%3A%2F%2Fcpa-gw.bhyoo.com")"
          if [ "$HTTP_CODE" != "200" ]; then
            MSG="$(jq -r '(.message // .error // empty) | tostring' "$BODY" 2>/dev/null | tr '\r\n' '  ' | head -c 160 || true)"
            echo "::error::[cpa-oidc] stage=github-oidc http=${HTTP_CODE} message=${MSG}"
            exit 1
          fi
          JWT="$(jq -r '.value // empty' "$BODY")"
          test -n "$JWT"
          echo "::add-mask::${JWT}"

          HTTP_CODE="$(curl -sS -D "$HDR" -o "$BODY" -w '%{http_code}' -X POST "https://cpa-gw.bhyoo.com/oidc/v1/token" \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -H "Accept: application/json" \
            --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
            --data-urlencode "subject_token_type=urn:ietf:params:oauth:token-type:jwt" \
            --data-urlencode "subject_token=${JWT}")"
          if [ "$HTTP_CODE" != "200" ]; then
            hdr() { awk -v k="$1" 'tolower($0) ~ "^" k ":[ \t]*" {sub(/^[^:]*:[ \t]*/, ""); sub(/\r$/, ""); print; exit}' "$HDR" 2>/dev/null || true; }
            CT="$(hdr content-type)"
            SRV="$(hdr server)"
            CF_RAY="$(hdr cf-ray)"
            CF_MIT="$(hdr cf-mitigated)"
            ERR="$(jq -r '(.error // empty) | tostring' "$BODY" 2>/dev/null || true)"
            if [ -z "$ERR" ]; then
              ERR="$(tr '\r\n' '  ' < "$BODY" | grep -oi '<title[^>]*>[^<]*</title>' | head -n 1 | sed 's/<[^>]*>//g' | head -c 80 || true)"
            fi
            echo "::error::[cpa-oidc] stage=cpa-gw http=${HTTP_CODE} content_type=${CT} server=${SRV} cf_ray=${CF_RAY} cf_mitigated=${CF_MIT} error=${ERR}"
            exit 1
          fi
          TOKEN="$(jq -r '.access_token // empty' "$BODY")"
          test -n "$TOKEN"
          echo "::add-mask::${TOKEN}"
          echo "token=${TOKEN}" >> "$GITHUB_OUTPUT"
---
