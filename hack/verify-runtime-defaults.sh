#!/usr/bin/env bash
# Verify rendered runtime defaults for both packaging surfaces: the Helm chart
# and the Kustomize base must set the Go runtime env defaults and the production
# logging args on the container named "manager". With file arguments, check
# those pre-rendered manifests instead of rendering (used by QA mutations).
set -euo pipefail

helm_bin=${HELM:-helm}
kustomize_bin=${KUSTOMIZE:-kustomize}
chart_dir=${CHART_DIR:-charts/flareway}
release=${CHART_RELEASE_NAME:-flareway}
namespace=${CHART_NAMESPACE:-flareway-system}
kustomize_dir=${KUSTOMIZE_DIR:-config/default}

tmp=$(mktemp -d)
trap 'rm -rf "${tmp}"' EXIT

# Print the args of the container named "manager"; exit 1 if none are found.
# A container list item may place "name:" before "args:" (Helm style) or after
# it (Kustomize alphabetizes mapping keys), so each list item is buffered and
# judged only when it ends.
manager_args_awk='
function flush_item(    i) {
  if (in_item && is_manager && item_args_n > 0) {
    for (i = 1; i <= item_args_n; i++) print item_args[i]
    found = 1
  }
}
{
  line = $0
  indent = 0
  while (substr(line, indent + 1, 1) == " ") indent++
  text = substr(line, indent + 1)
  sub(/[ \t]+$/, "", text)
  if (text == "" || substr(text, 1, 1) == "#") next

  dash = (substr(text, 1, 2) == "- ")
  content = dash ? substr(text, 3) : text
  content_col = dash ? indent + 2 : indent

  if (in_args) {
    if (dash && indent >= args_indent) {
      sub(/^"/, "", content); sub(/"$/, "", content)
      item_args[++item_args_n] = content
      next
    }
    in_args = 0
  }

  if (in_item && indent <= item_indent) { flush_item(); in_item = 0 }

  if (dash) {
    if (!in_item) {
      if (content ~ /^[A-Za-z][A-Za-z0-9_.-]*:([ \t]|$)/) {
        in_item = 1; is_manager = 0; item_args_n = 0
        item_indent = indent; key_indent = content_col
      } else {
        next
      }
    } else {
      next
    }
  }

  if (!in_item || content_col != key_indent) next

  if (content ~ /^name:[ \t]+"?manager"?[ \t]*$/) is_manager = 1
  else if (content ~ /^args:[ \t]*$/) { in_args = 1; args_indent = content_col }
}
END { if (in_item) flush_item(); exit(found ? 0 : 1) }
'

# Require GOMEMLIMIT=115MiB and GODEBUG=tracebacklabels=0, and no GOMAXPROCS.
env_defaults_awk='
$1 == "-" && $2 == "name:" {
  current = $3
  if (current == "GOMAXPROCS") invalid = 1
  next
}
current == "GOMEMLIMIT" && $1 == "value:" {
  if ($2 == "115MiB" || $2 == "\"115MiB\"") memory = 1
  current = ""
}
current == "GODEBUG" && $1 == "value:" {
  if ($2 == "tracebacklabels=0" || $2 == "\"tracebacklabels=0\"") debug = 1
  current = ""
}
END { exit !(memory && debug && !invalid) }
'

check_env_defaults() {
  local label=$1 manifest=$2
  if ! awk "${env_defaults_awk}" "${manifest}"; then
    echo "${label}: must set GOMEMLIMIT=115MiB and GODEBUG=tracebacklabels=0 without GOMAXPROCS" >&2
    return 1
  fi
}

# The manager container args must contain each expected --zap-* arg exactly
# once and no other value for those flags.
check_zap_args() {
  local label=$1 manifest=$2 devel=$3 level=$4 encoder=$5
  local args_file="${tmp}/manager-args.txt"
  if ! awk "${manager_args_awk}" "${manifest}" >"${args_file}"; then
    echo "${label}: no args found for container \"manager\"" >&2
    return 1
  fi
  local spec flag count extra
  for spec in "--zap-devel=${devel}" "--zap-log-level=${level}" "--zap-encoder=${encoder}"; do
    flag=${spec%%=*}
    count=$(grep -c -x -- "${spec}" "${args_file}" || true)
    if [[ ${count} -eq 0 ]]; then
      echo "${label}: container \"manager\" is missing required arg ${spec}" >&2
      return 1
    elif [[ ${count} -ne 1 ]]; then
      echo "${label}: container \"manager\" has arg ${spec} ${count} times (expected exactly once)" >&2
      return 1
    fi
    extra=$(grep -E -- "^${flag}(=|$)" "${args_file}" | grep -v -x -- "${spec}" || true)
    if [[ -n ${extra} ]]; then
      echo "${label}: container \"manager\" has unexpected ${flag} arg(s): ${extra} (only ${spec} is allowed)" >&2
      return 1
    fi
  done
}

check_manifest() {
  check_env_defaults "$1" "$2"
  check_zap_args "$1" "$2" false info json
}

if (($# > 0)); then
  for manifest in "$@"; do
    check_manifest "${manifest}" "${manifest}"
  done
  exit 0
fi

"${helm_bin}" template "${release}" "${chart_dir}" --namespace "${namespace}" --include-crds >"${tmp}/helm.yaml"
"${helm_bin}" template "${release}" "${chart_dir}" --namespace "${namespace}" --include-crds \
  --set logging.development=true --set logging.level=debug --set logging.encoder=console >"${tmp}/helm-development.yaml"
"${kustomize_bin}" build "${kustomize_dir}" >"${tmp}/kustomize.yaml"

check_manifest "Helm render" "${tmp}/helm.yaml"
check_manifest "Kustomize render" "${tmp}/kustomize.yaml"
check_zap_args "Helm render (logging.development=true logging.level=debug logging.encoder=console)" \
  "${tmp}/helm-development.yaml" true debug console
