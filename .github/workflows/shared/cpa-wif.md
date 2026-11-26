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
      JWT="$(curl -fsSL -H "Authorization: Bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
        "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=https://cpa-gw.bhyoo.com" | jq -r '.value')"
      test -n "$JWT" && [ "$JWT" != "null" ]
      echo "::add-mask::${JWT}"
      TOKEN="$(curl -fsSL -X POST "https://cpa-gw.bhyoo.com/oidc/v1/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -H "Accept: application/json" \
        --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
        --data-urlencode "subject_token_type=urn:ietf:params:oauth:token-type:jwt" \
        --data-urlencode "subject_token=${JWT}" | jq -r '.access_token')"
      test -n "$TOKEN" && [ "$TOKEN" != "null" ]
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
          JWT="$(curl -fsSL -H "Authorization: Bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
            "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=https://cpa-gw.bhyoo.com" | jq -r '.value')"
          test -n "$JWT" && [ "$JWT" != "null" ]
          echo "::add-mask::${JWT}"
          TOKEN="$(curl -fsSL -X POST "https://cpa-gw.bhyoo.com/oidc/v1/token" \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -H "Accept: application/json" \
            --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
            --data-urlencode "subject_token_type=urn:ietf:params:oauth:token-type:jwt" \
            --data-urlencode "subject_token=${JWT}" | jq -r '.access_token')"
          test -n "$TOKEN" && [ "$TOKEN" != "null" ]
          echo "::add-mask::${TOKEN}"
          echo "token=${TOKEN}" >> "$GITHUB_OUTPUT"
---
