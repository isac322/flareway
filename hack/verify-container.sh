#!/usr/bin/env bash

set -euo pipefail

container_tool="${CONTAINER_TOOL:-docker}"
image="${IMG:-controller:latest}"
max_compressed_size="${MAX_COMPRESSED_IMAGE_SIZE_BYTES:-67108864}"

fail() {
  printf 'container verification failed: %s\n' "$*" >&2
  exit 1
}

user="$("${container_tool}" image inspect --format '{{.Config.User}}' "${image}")"
[[ "${user}" == "65532:65532" ]] || fail "expected user 65532:65532, got ${user:-<empty>}"

entrypoint="$("${container_tool}" image inspect --format '{{json .Config.Entrypoint}}' "${image}")"
[[ "${entrypoint}" == '["/manager"]' ]] || fail "expected entrypoint [\"/manager\"], got ${entrypoint}"

"${container_tool}" run --rm "${image}" --help >/dev/null 2>&1

tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT
mkdir -p "${tmp}/image" "${tmp}/rootfs"

"${container_tool}" image save --output "${tmp}/image.tar" "${image}"
tar -xf "${tmp}/image.tar" -C "${tmp}/image"
mapfile -t layers < <(python3 - "${tmp}/image/manifest.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as manifest_file:
    manifests = json.load(manifest_file)
if len(manifests) != 1:
    raise SystemExit(f"expected one image manifest, got {len(manifests)}")
for layer in manifests[0]["Layers"]:
    print(layer)
PY
)
((${#layers[@]} > 0)) || fail "docker image export did not contain any filesystem layers"
for layer in "${layers[@]}"; do
  tar -xf "${tmp}/image/${layer}" -C "${tmp}/rootfs"
done

files="$(cd "${tmp}/rootfs" && find . \( -type f -o -type l \) -print | LC_ALL=C sort)"
expected_files=$'./etc/ssl/certs/ca-certificates.crt\n./manager'
if [[ "${files}" != "${expected_files}" ]]; then
  printf 'container verification failed: scratch filesystem must contain only /manager and the CA bundle; found:\n%s\n' \
    "${files}" >&2
  exit 1
fi

gzip -9 -c "${tmp}/image.tar" >"${tmp}/image.tar.gz"
compressed_size="$(wc -c <"${tmp}/image.tar.gz")"
compressed_size="${compressed_size//[[:space:]]/}"
((compressed_size <= max_compressed_size)) || fail "compressed image is ${compressed_size} bytes; limit is ${max_compressed_size} bytes"

printf 'Verified %s: non-root scratch image, expected runtime metadata, working --help, %s-byte compressed export.\n' \
  "${image}" "${compressed_size}"
