#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

BIN_DIR="${LOCALBIN:-${ROOT_DIR}/bin}"
KIND_BIN="${KIND_LOCAL:-${BIN_DIR}/kind}"
KO_BIN="${KO:-${BIN_DIR}/ko}"
KUSTOMIZE_BIN="${KUSTOMIZE:-${BIN_DIR}/kustomize}"
CLOUD_PROVIDER_KIND_BIN="${CLOUD_PROVIDER_KIND:-${BIN_DIR}/cloud-provider-kind}"

KIND_VERSION="${KIND_VERSION:-v0.33.0}"
KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-flareway-conf}"
KIND_NODE_IMAGE="${KIND_NODE_IMAGE:-kindest/node:v1.35.0}"
GATEWAY_API_VERSION="${GATEWAY_API_VERSION:-v1.6.2}"
KO_VERSION="${KO_VERSION:-v0.19.1}"
KUSTOMIZE_VERSION="${KUSTOMIZE_VERSION:-v5.8.1}"
CLOUD_PROVIDER_KIND_VERSION="${CLOUD_PROVIDER_KIND_VERSION:-v0.11.1}"
TARGET_ARCH="${TARGET_ARCH:-$(go env GOARCH)}"
VERSION="${VERSION:-}"
RUN_TEST="${CONFORMANCE_RUN_TEST:-}"

if [[ -z "${VERSION}" ]]; then
  VERSION="$(git rev-parse --short=12 HEAD 2>/dev/null || true)"
  VERSION="${VERSION:-dev}"
fi

REPORT_OUTPUT="${REPORT_OUTPUT:-conformance/reports/v1.6.2/flareway/standard-${VERSION}-default-report.yaml}"
if [[ "${REPORT_OUTPUT}" != /* ]]; then
  REPORT_OUTPUT="${ROOT_DIR}/${REPORT_OUTPUT}"
fi

ARTIFACT_DIR="${CONFORMANCE_ARTIFACT_DIR:-${ROOT_DIR}/artifacts/conformance}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/flareway-conformance.XXXXXX")"
KUBECONFIG_FILE="${CONFORMANCE_KUBECONFIG:-${TMP_DIR}/kubeconfig}"
export KUBECONFIG="${KUBECONFIG_FILE}"
PROVIDER_PID=""
CLUSTER_READY=false

cleanup() {
  local status=$?
  if [[ -n "${PROVIDER_PID}" ]] && kill -0 "${PROVIDER_PID}" 2>/dev/null; then
    kill "${PROVIDER_PID}" 2>/dev/null || true
    wait "${PROVIDER_PID}" 2>/dev/null || true
  fi
  if [[ "${CLUSTER_READY}" == true ]]; then
    mkdir -p "${ARTIFACT_DIR}"
    kubectl -n flareway-system logs deployment/flareway-controller-manager \
      --all-containers --ignore-errors > "${ARTIFACT_DIR}/controller.log" 2>&1 || true
    kubectl -n flareway-system describe deployment/flareway-controller-manager \
      > "${ARTIFACT_DIR}/controller-deployment.txt" 2>&1 || true
    kubectl get gatewayclasses,gateways,httproutes,referencegrants,backendtlspolicies \
      -A -o yaml > "${ARTIFACT_DIR}/gateway-api-resources.yaml" 2>&1 || true
    kubectl get deployments,services,pods,endpointslices \
      -A -o wide > "${ARTIFACT_DIR}/kubernetes-resources.txt" 2>&1 || true
    kubectl get events -A --sort-by=.lastTimestamp \
      > "${ARTIFACT_DIR}/events.txt" 2>&1 || true
  fi
  rm -rf "${TMP_DIR}"
  exit "${status}"
}
trap cleanup EXIT INT TERM

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "required command not found: $1" >&2
    exit 1
  fi
}

install_tool() {
  local output=$1
  local module=$2
  local version=$3
  if [[ ! -x "${output}" ]]; then
    mkdir -p "$(dirname "${output}")"
    echo "Installing ${module}@${version}"
    GOBIN="$(dirname "${output}")" go install "${module}@${version}"
  fi
}

require_command docker
require_command go
require_command kubectl
require_command git

install_tool "${KIND_BIN}" sigs.k8s.io/kind "${KIND_VERSION}"
install_tool "${KO_BIN}" github.com/google/ko "${KO_VERSION}"
install_tool "${KUSTOMIZE_BIN}" sigs.k8s.io/kustomize/kustomize/v5 "${KUSTOMIZE_VERSION}"

if ! "${KIND_BIN}" get clusters | grep -Fxq "${KIND_CLUSTER_NAME}"; then
  node_args=()
  if docker image inspect "${KIND_NODE_IMAGE}" >/dev/null 2>&1 || \
     docker manifest inspect "${KIND_NODE_IMAGE}" >/dev/null 2>&1; then
    node_args=(--image "${KIND_NODE_IMAGE}")
    echo "Using requested kind node image: ${KIND_NODE_IMAGE}"
  else
    echo "Warning: ${KIND_NODE_IMAGE} is unavailable; using the kind ${KIND_VERSION} default node image" >&2
  fi
  "${KIND_BIN}" create cluster \
    --name "${KIND_CLUSTER_NAME}" \
    --config hack/kind-config.yaml \
    --kubeconfig "${KUBECONFIG_FILE}" \
    "${node_args[@]}"
else
  echo "Reusing kind cluster ${KIND_CLUSTER_NAME}"
  "${KIND_BIN}" export kubeconfig \
    --name "${KIND_CLUSTER_NAME}" \
    --kubeconfig "${KUBECONFIG_FILE}"
fi

kubectl config use-context "kind-${KIND_CLUSTER_NAME}" >/dev/null
CLUSTER_READY=true
kubectl get nodes -o wide

kubectl apply --server-side -f \
  "https://github.com/kubernetes-sigs/gateway-api/releases/download/${GATEWAY_API_VERSION}/standard-install.yaml"
kubectl wait --for=condition=Established --timeout=2m \
  customresourcedefinition/gatewayclasses.gateway.networking.k8s.io \
  customresourcedefinition/gateways.gateway.networking.k8s.io \
  customresourcedefinition/httproutes.gateway.networking.k8s.io

controller_image=""
if git rev-parse --verify HEAD >/dev/null 2>&1 && controller_image="$(
  KO_DOCKER_REPO=kind.local \
  KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME}" \
  "${KO_BIN}" build --platform="linux/${TARGET_ARCH}" --bare ./cmd
)"; then
  echo "Built controller image ${controller_image} with ko"
else
  echo "ko needs a committed revision and a working kind publisher; using a local Docker image instead" >&2
  controller_tag="flareway-controller:${VERSION//[^a-zA-Z0-9_.-]/-}"
  CGO_ENABLED=0 GOOS=linux GOARCH="${TARGET_ARCH}" \
    go build -o "${TMP_DIR}/manager" ./cmd
  cat > "${TMP_DIR}/ControllerDockerfile" <<'EOF'
FROM cgr.dev/chainguard/static:latest@sha256:bf639cba19ba56329e6907ac26a7afcdde57a80b6aa66d5100da6883196e6b82
COPY manager /manager
USER 65532:65532
ENTRYPOINT ["/manager"]
EOF
  docker build --platform="linux/${TARGET_ARCH}" \
    -f "${TMP_DIR}/ControllerDockerfile" -t "${controller_tag}" "${TMP_DIR}"
  "${KIND_BIN}" load docker-image --name "${KIND_CLUSTER_NAME}" "${controller_tag}"
  controller_image="${controller_tag}"
fi

kubectl apply --server-side -k config/crd
"${KUSTOMIZE_BIN}" build config/default | \
  sed "s|image: controller:latest|image: ${controller_image}|" | \
  kubectl apply -f -
kubectl -n flareway-system rollout status \
  deployment/flareway-controller-manager --timeout=5m

mkdir -p "$(dirname "${REPORT_OUTPUT}")" "${ARTIFACT_DIR}"

run_mode=in-cluster
if [[ "$(uname -s)" == Linux ]]; then
  install_tool "${CLOUD_PROVIDER_KIND_BIN}" sigs.k8s.io/cloud-provider-kind "${CLOUD_PROVIDER_KIND_VERSION}"
  "${CLOUD_PROVIDER_KIND_BIN}" > "${ARTIFACT_DIR}/cloud-provider-kind.log" 2>&1 &
  PROVIDER_PID=$!

  kubectl create namespace flareway-conformance-lb-probe --dry-run=client -o yaml | kubectl apply -f -
  cat <<'EOF' | kubectl apply -f -
apiVersion: v1
kind: Service
metadata:
  name: load-balancer
  namespace: flareway-conformance-lb-probe
spec:
  type: LoadBalancer
  selector:
    app: no-pods-required
  ports:
    - name: http
      port: 18080
      targetPort: 18080
EOF

  provider_ready=false
  for _ in $(seq 1 30); do
    if ! kill -0 "${PROVIDER_PID}" 2>/dev/null; then
      break
    fi
    address="$(kubectl -n flareway-conformance-lb-probe get service load-balancer \
      -o jsonpath='{.status.loadBalancer.ingress[0].ip}{.status.loadBalancer.ingress[0].hostname}' 2>/dev/null || true)"
    if [[ -n "${address}" ]]; then
      provider_ready=true
      break
    fi
    sleep 2
  done
  kubectl delete namespace flareway-conformance-lb-probe --wait=false >/dev/null 2>&1 || true

  if [[ "${provider_ready}" == true ]]; then
    run_mode=host
    echo "cloud-provider-kind assigned a LoadBalancer address; running the suite from the host"
  else
    echo "cloud-provider-kind did not assign a LoadBalancer address; using the ClusterIP in-cluster runner" >&2
    if kill -0 "${PROVIDER_PID}" 2>/dev/null; then
      kill "${PROVIDER_PID}" 2>/dev/null || true
      wait "${PROVIDER_PID}" 2>/dev/null || true
    fi
    PROVIDER_PID=""
  fi
else
  echo "$(uname -s) does not support unprivileged cloud-provider-kind; using the ClusterIP in-cluster runner"
fi

if [[ "${run_mode}" == host ]]; then
  kubectl apply -f test/conformance/manifests/gatewayclassconfig-conformance.yaml
else
  kubectl apply -f test/conformance/manifests/gatewayclassconfig-conformance-clusterip.yaml
fi
kubectl apply -f test/conformance/manifests/gatewayclass.yaml
kubectl wait --for=condition=Accepted gatewayclass/flareway --timeout=2m

suite_args=(-report-output="${REPORT_OUTPUT}")
if [[ -n "${RUN_TEST}" ]]; then
  suite_args+=(-run-test="${RUN_TEST}")
  echo "Running only conformance test ${RUN_TEST}"
fi

if [[ "${run_mode}" == host ]]; then
  go test -tags conformance -timeout 60m -count=1 -v \
    -ldflags "-X github.com/isac322/flareway/test/conformance.version=${VERSION}" \
    ./test/conformance/... -run TestConformance -args \
    "${suite_args[@]}"
  exit 0
fi

runner_image="flareway-conformance-runner:${VERSION}"
CGO_ENABLED=0 GOOS=linux GOARCH="${TARGET_ARCH}" \
  go test -c -tags conformance \
  -ldflags "-X github.com/isac322/flareway/test/conformance.version=${VERSION}" \
  -o "${TMP_DIR}/conformance.test" ./test/conformance
cat > "${TMP_DIR}/runner-entrypoint.sh" <<'EOF'
#!/bin/sh
set +e
/usr/local/bin/conformance.test "$@"
status=$?
if [ -f /reports/report.yaml ]; then
  echo "__FLAREWAY_CONFORMANCE_REPORT_BEGIN__"
  base64 /reports/report.yaml
  echo "__FLAREWAY_CONFORMANCE_REPORT_END__"
fi
exit "${status}"
EOF
cat > "${TMP_DIR}/Dockerfile" <<'EOF'
FROM alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce
COPY conformance.test /usr/local/bin/conformance.test
COPY runner-entrypoint.sh /usr/local/bin/runner-entrypoint.sh
ENTRYPOINT ["/bin/sh", "/usr/local/bin/runner-entrypoint.sh"]
EOF
docker build --platform="linux/${TARGET_ARCH}" -t "${runner_image}" "${TMP_DIR}"
"${KIND_BIN}" load docker-image --name "${KIND_CLUSTER_NAME}" "${runner_image}"

kubectl apply -f test/conformance/manifests/runner-rbac.yaml
job_name="flareway-conformance-${VERSION//[^a-zA-Z0-9-]/-}"
job_name="${job_name:0:63}"
kubectl -n flareway-conformance-runner delete job "${job_name}" --ignore-not-found >/dev/null
run_test_yaml=""
if [[ -n "${RUN_TEST}" ]]; then
  run_test_yaml="            - -run-test=${RUN_TEST}"
fi
cat > "${TMP_DIR}/runner-job.yaml" <<EOF
apiVersion: batch/v1
kind: Job
metadata:
  name: ${job_name}
  namespace: flareway-conformance-runner
spec:
  backoffLimit: 0
  activeDeadlineSeconds: 3900
  template:
    metadata:
      labels:
        app.kubernetes.io/name: flareway-conformance-runner
    spec:
      restartPolicy: Never
      serviceAccountName: runner
      containers:
        - name: runner
          image: ${runner_image}
          imagePullPolicy: Never
          args:
            - -test.v
            - -test.timeout=60m
            - -test.run=TestConformance
            - -report-output=/reports/report.yaml
${run_test_yaml}
          volumeMounts:
            - name: reports
              mountPath: /reports
      volumes:
        - name: reports
          emptyDir: {}
EOF
kubectl apply -f "${TMP_DIR}/runner-job.yaml"

pod_name=""
for _ in $(seq 1 60); do
  pod_name="$(kubectl -n flareway-conformance-runner get pods \
    -l "job-name=${job_name}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
  [[ -n "${pod_name}" ]] && break
  sleep 1
done
if [[ -z "${pod_name}" ]]; then
  echo "conformance runner Pod was not created" >&2
  exit 1
fi

phase=""
for _ in $(seq 1 780); do
  phase="$(kubectl -n flareway-conformance-runner get pod "${pod_name}" \
    -o jsonpath='{.status.phase}' 2>/dev/null || true)"
  case "${phase}" in
    Succeeded|Failed)
      break
      ;;
  esac
  sleep 5
done

runner_log="${ARTIFACT_DIR}/conformance-runner.log"
kubectl -n flareway-conformance-runner logs "${pod_name}" > "${runner_log}" 2>&1 || true
awk '
  /__FLAREWAY_CONFORMANCE_REPORT_BEGIN__/ { copying = 1; next }
  /__FLAREWAY_CONFORMANCE_REPORT_END__/ { copying = 0 }
  copying { print }
' "${runner_log}" > "${TMP_DIR}/report.b64"
if [[ -s "${TMP_DIR}/report.b64" ]]; then
  if ! base64 --decode < "${TMP_DIR}/report.b64" > "${REPORT_OUTPUT}" 2>/dev/null; then
    base64 -D < "${TMP_DIR}/report.b64" > "${REPORT_OUTPUT}"
  fi
else
  echo "the in-cluster runner did not emit a conformance report" >&2
  tail -n 100 "${runner_log}" >&2
  exit 1
fi

if [[ "${phase}" != Succeeded ]]; then
  echo "the in-cluster conformance runner finished with Pod phase ${phase:-unknown}" >&2
  tail -n 100 "${runner_log}" >&2
  exit 1
fi

echo "Conformance report written to ${REPORT_OUTPUT}"
