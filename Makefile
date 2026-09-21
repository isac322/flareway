# Image URL to use all building/pushing image targets
IMG ?= controller:latest
KO_DOCKER_REPO ?= ghcr.io/isac322/flareway
KIND_CLUSTER_NAME ?= flareway-conf
KIND_NODE_IMAGE ?= kindest/node:v1.35.0
FLAREWAY_E2E_LABELS ?= public,access
EXPLORATORY_CHECKS ?= 25
EXPLORATORY_STEPS ?= 8
EXPLORATORY_SEED ?= 1
EXPLORATORY_TEST_TIMEOUT ?= 15m
EXPLORATORY_ARTIFACT_DIR ?= $(LOCALBIN)/exploratory-artifacts
EXPLORATORY_TEST_BINARY ?= $(LOCALBIN)/flareway-exploratory.test
CHART_DIR ?= charts/flareway
CHART_RELEASE_NAME ?= flareway
CHART_NAMESPACE ?= flareway-system
CHART_DIST ?= dist
LOCALBIN ?= $(shell pwd)/bin
# A stripped static Go controller plus the CA bundle should remain well below 64 MiB compressed.
MAX_COMPRESSED_IMAGE_SIZE_BYTES ?= 67108864
# YEAR defines the year value used for substituting the YEAR placeholder in the boilerplate header.
YEAR ?= $(shell date +%Y)

# Extra flags for `go test` invocations that CI parameterizes.
GO_TEST_FLAGS ?=
# `-exec true` links each test binary and hands it to `true` instead of running
# it; `-count=1` keeps those unexecuted runs out of the Go test result cache so
# a later real run still executes the tests.
COMPILE_ONLY_TEST_FLAGS := -count=1 -exec true

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# CONTAINER_TOOL defines the container tool to be used for building images.
# Be aware that the target commands are only tested with Docker which is
# scaffolded by default. However, you might want to replace it to use other
# tools. (i.e. podman)
CONTAINER_TOOL ?= docker

# Setting SHELL to bash allows bash commands to be executed by recipes.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

.PHONY: all
all: build

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk command is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: manifests
manifests: controller-gen ## Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects.
	"$(CONTROLLER_GEN)" rbac:roleName=manager-role crd webhook paths="./..." output:crd:artifacts:config=config/crd/bases
	"$(MAKE)" sync-chart-crds

.PHONY: sync-chart-crds
sync-chart-crds: ## Synchronize generated Flareway CRDs into the Helm chart.
	mkdir -p "$(CHART_DIR)/crds"
	rm -f "$(CHART_DIR)"/crds/flareway.bhyoo.com_*.yaml
	cp config/crd/bases/flareway.bhyoo.com_*.yaml "$(CHART_DIR)/crds/"

.PHONY: generate
generate: controller-gen ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	"$(CONTROLLER_GEN)" object:headerFile="hack/boilerplate.go.txt",year=$(YEAR) paths="./..."

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: parity
parity: ## Verify Cloudflare SDK schema parity and ledger ownership.
	go run ./hack/parity

.PHONY: gateway-api-crds
gateway-api-crds: ## Print the Gateway API standard CRD directory from the module cache.
	@printf '%s/config/crd/standard\n' "$$(go list -m -f '{{.Dir}}' sigs.k8s.io/gateway-api)"

.PHONY: test-unit
test-unit: ## Run unit tests outside the controller envtest package.
	go test $$(go list ./... | grep -v /internal/controller)

.PHONY: test-envtest
test-envtest: setup-envtest ## Run controller tests with envtest.
	KUBEBUILDER_ASSETS="$$( "$(ENVTEST)" use $(ENVTEST_K8S_VERSION) --bin-dir "$(LOCALBIN)" -p path)" go test ./internal/controller/...

.PHONY: test-exploratory-compile
test-exploratory-compile: ## Vet the tagged harness and run its deterministic artifact-safety tests.
	go vet -tags exploratory ./test/exploratory
	go test -race -tags exploratory -run '^TestTrace' ./test/exploratory

.PHONY: test-exploratory
test-exploratory: setup-envtest ## Run bounded state-machine exploration against an isolated envtest control plane.
	@for value in "$(EXPLORATORY_SEED)" "$(EXPLORATORY_CHECKS)" "$(EXPLORATORY_STEPS)"; do \
		if [[ ! "$$value" =~ ^[1-9][0-9]*$$ ]]; then \
			echo "EXPLORATORY_SEED, EXPLORATORY_CHECKS, and EXPLORATORY_STEPS must be positive integers"; \
			exit 1; \
		fi; \
	done
	@mkdir -p "$(EXPLORATORY_ARTIFACT_DIR)"
	go test -c -tags exploratory -race -o "$(EXPLORATORY_TEST_BINARY)" ./test/exploratory
	@assets="$$( "$(ENVTEST)" use $(ENVTEST_K8S_VERSION) --bin-dir "$(LOCALBIN)" -p path)"; \
		artifact_dir="$$(cd "$(EXPLORATORY_ARTIFACT_DIR)" && pwd)"; \
		repository_root="$$(pwd)"; \
		cd "$$artifact_dir"; \
		rm -rf "$$artifact_dir/testdata"; \
		for test_name in TestAccessStateMachine TestGatewayStateMachine TestNetworkRouteStateMachine TestSmokeAccountVerificationRoundTrip; do \
			KUBEBUILDER_ASSETS="$$assets" \
			FLAREWAY_REPOSITORY_ROOT="$$repository_root" \
			FLAREWAY_EXPLORATORY_ARTIFACT_DIR="$$artifact_dir" \
			"$(EXPLORATORY_TEST_BINARY)" -test.run="^$${test_name}$$" -test.timeout="$(EXPLORATORY_TEST_TIMEOUT)" \
			-rapid.checks="$(EXPLORATORY_CHECKS)" \
			-rapid.steps="$(EXPLORATORY_STEPS)" \
			-rapid.seed="$(EXPLORATORY_SEED)" || exit; \
		done

.PHONY: test
test: test-unit test-envtest ## Run unit and envtest test suites.

.PHONY: test-envoy
test-envoy: $(LOCALBIN) ## Run Envoy component tests without rewriting the pinned toolchain directive.
	@tmp="$$(mktemp -d "$(LOCALBIN)/flareway-envoy.XXXXXX")"; \
	mod="$$tmp/flareway.mod"; \
	trap 'rm -rf "$$tmp"' EXIT; \
	cp go.mod "$$mod"; \
	cp go.sum "$${mod%.mod}.sum"; \
	go mod edit -modfile="$$mod" -toolchain=none; \
	go test $(GO_TEST_FLAGS) -modfile="$$mod" -tags envoy ./test/envoy/...

.PHONY: warm-build-cache
warm-build-cache: ## Compile every Go artifact CI builds, populating the shared Go build cache.
	go build ./...
	go vet ./...
	go test $(COMPILE_ONLY_TEST_FLAGS) ./...
	go vet -tags exploratory ./test/exploratory
	go test $(COMPILE_ONLY_TEST_FLAGS) -race -tags exploratory ./test/exploratory
	go test $(COMPILE_ONLY_TEST_FLAGS) -tags e2e ./test/e2e
	$(MAKE) test-envoy GO_TEST_FLAGS='$(COMPILE_ONLY_TEST_FLAGS)'
	CGO_ENABLED=0 GOOS=linux go build -o /dev/null ./cmd
	CGO_ENABLED=0 GOOS=linux go test -c -tags conformance -o /dev/null ./test/conformance
	$(MAKE) controller-gen golangci-lint kustomize kind ko helm cosign envtest cloud-provider-kind

.PHONY: kind-up
kind-up: kind ## Create the conformance Kind cluster if it does not exist.
	@case "$$("$(KIND_LOCAL)" get clusters)" in \
		*"$(KIND_CLUSTER_NAME)"*) \
			echo "Kind cluster '$(KIND_CLUSTER_NAME)' already exists. Skipping creation." ;; \
		*) \
			"$(KIND_LOCAL)" create cluster --name "$(KIND_CLUSTER_NAME)" --config hack/kind-config.yaml --image "$(KIND_NODE_IMAGE)" ;; \
	esac

.PHONY: conformance
conformance: ## Run the portable Gateway API conformance workflow.
	hack/run-conformance.sh

.PHONY: e2e
e2e: ## Run Cloudflare end-to-end tests serially.
	go test -tags e2e -timeout 60m ./test/e2e -ginkgo.label-filter="$(FLAREWAY_E2E_LABELS)"

.PHONY: e2e-janitor
e2e-janitor: ## Remove stale Cloudflare end-to-end test resources.
	go run ./test/e2e/internal/janitor/cmd -older-than 2h

# TODO(user): To use a different vendor for e2e tests, modify the setup under 'tests/e2e'.
# The default setup assumes Kind is pre-installed and builds/loads the Manager Docker image locally.
# kubectl kuberc is disabled by default for test isolation; enable with:
# - KUBECTL_KUBERC=true
# CertManager is installed by default; skip with:
# - CERT_MANAGER_INSTALL_SKIP=true
KIND_CLUSTER ?= flareway-test-e2e

.PHONY: setup-test-e2e
setup-test-e2e: ## Set up a Kind cluster for e2e tests if it does not exist
	@command -v $(KIND) >/dev/null 2>&1 || { \
		echo "Kind is not installed. Please install Kind manually."; \
		exit 1; \
	}
	@case "$$($(KIND) get clusters)" in \
		*"$(KIND_CLUSTER)"*) \
			echo "Kind cluster '$(KIND_CLUSTER)' already exists. Skipping creation." ;; \
		*) \
			echo "Creating Kind cluster '$(KIND_CLUSTER)'..."; \
			$(KIND) create cluster --name $(KIND_CLUSTER) ;; \
	esac

.PHONY: test-e2e
test-e2e: setup-test-e2e manifests generate fmt vet ## Run the e2e tests. Expected an isolated environment using Kind.
	KIND=$(KIND) KIND_CLUSTER=$(KIND_CLUSTER) go test -tags=e2e ./test/e2e/ -v -ginkgo.v
	$(MAKE) cleanup-test-e2e

.PHONY: cleanup-test-e2e
cleanup-test-e2e: ## Tear down the Kind cluster used for e2e tests
	@$(KIND) delete cluster --name $(KIND_CLUSTER)

.PHONY: lint
lint: golangci-lint ## Run golangci-lint linter
	"$(GOLANGCI_LINT)" run

.PHONY: lint-fix
lint-fix: golangci-lint ## Run golangci-lint linter and perform fixes
	"$(GOLANGCI_LINT)" run --fix

.PHONY: lint-config
lint-config: golangci-lint ## Verify golangci-lint linter configuration
	"$(GOLANGCI_LINT)" config verify

##@ Verification

.PHONY: verify-generated
verify-generated: manifests generate ## Regenerate tracked artifacts and fail if the worktree changes.
	git diff --exit-code HEAD --
	@untracked="$$(git ls-files --others --exclude-standard)"; \
	if [ -n "$$untracked" ]; then \
		printf 'Untracked files remain after generation:\n%s\n' "$$untracked" >&2; \
		exit 1; \
	fi

.PHONY: verify-go-build
verify-go-build: ## Compile every Go package.
	go build ./...

.PHONY: verify-helm
verify-helm: helm ## Lint and render the Helm chart.
	"$(HELM)" lint "$(CHART_DIR)"
	"$(HELM)" template "$(CHART_RELEASE_NAME)" "$(CHART_DIR)" --namespace "$(CHART_NAMESPACE)" --include-crds >/dev/null

.PHONY: verify-kustomize
verify-kustomize: kustomize ## Render every supported Kustomize surface.
	@for directory in config/crd config/default config/samples; do \
		echo "Rendering $$directory"; \
		"$(KUSTOMIZE)" build "$$directory" >/dev/null; \
	done

.PHONY: verify-runtime-defaults
verify-runtime-defaults: helm kustomize ## Verify rendered runtime defaults for both packaging surfaces.
	@tmp="$$(mktemp -d)"; \
	trap 'rm -rf "$$tmp"' EXIT; \
	"$(HELM)" template "$(CHART_RELEASE_NAME)" "$(CHART_DIR)" --namespace "$(CHART_NAMESPACE)" --include-crds >"$$tmp/helm.yaml"; \
	"$(KUSTOMIZE)" build config/default >"$$tmp/kustomize.yaml"; \
	for manifest in "$$tmp/helm.yaml" "$$tmp/kustomize.yaml"; do \
		awk '\
			$$1 == "-" && $$2 == "name:" { \
				current = $$3; \
				if (current == "GOMAXPROCS") invalid = 1; \
				next; \
			} \
			current == "GOMEMLIMIT" && $$1 == "value:" { \
				if ($$2 == "115MiB" || $$2 == "\"115MiB\"") memory = 1; \
				current = ""; \
			} \
			current == "GODEBUG" && $$1 == "value:" { \
				if ($$2 == "tracebacklabels=0" || $$2 == "\"tracebacklabels=0\"") debug = 1; \
				current = ""; \
			} \
			END { exit !(memory && debug && !invalid) }' "$$manifest" || { \
				echo "$$manifest must set GOMEMLIMIT=115MiB and GODEBUG=tracebacklabels=0 without GOMAXPROCS" >&2; \
				exit 1; \
			}; \
	done

.PHONY: verify-artifacts
verify-artifacts: parity verify-go-build verify-helm verify-kustomize verify-runtime-defaults ## Verify schema parity, Go compilation, Helm, and Kustomize output.

##@ Build

.PHONY: build
build: manifests generate fmt vet ## Build manager binary.
	go build -o bin/manager cmd/main.go

.PHONY: run
run: manifests generate fmt vet ## Run a controller from your host.
	go run ./cmd/main.go

.PHONY: image
image: ko ## Build the operator image with ko.
	KO_DOCKER_REPO="$(KO_DOCKER_REPO)" "$(KO)" build --bare ./cmd

.PHONY: chart
chart: helm ## Lint, render, and package the Helm chart.
	mkdir -p "$(CHART_DIST)"
	"$(HELM)" lint "$(CHART_DIR)"
	"$(HELM)" template "$(CHART_RELEASE_NAME)" "$(CHART_DIR)" --namespace "$(CHART_NAMESPACE)" --include-crds >/dev/null
	"$(HELM)" package "$(CHART_DIR)" --destination "$(CHART_DIST)"

# Docker BuildKit builds the digest-pinned image declared by Dockerfile.
.PHONY: docker-build
docker-build: ## Build the manager image with Docker BuildKit.
	$(CONTAINER_TOOL) buildx build --load -t ${IMG} .

.PHONY: verify-container
verify-container: docker-build ## Verify the image filesystem, metadata, startup, and compressed size.
	CONTAINER_TOOL="$(CONTAINER_TOOL)" IMG="$(IMG)" MAX_COMPRESSED_IMAGE_SIZE_BYTES="$(MAX_COMPRESSED_IMAGE_SIZE_BYTES)" hack/verify-container.sh

.PHONY: docker-push
docker-push: ## Push docker image with the manager.
	$(CONTAINER_TOOL) push ${IMG}

# PLATFORMS optionally overrides the Linux platforms discovered from Dockerfile's pinned Go builder image.
PLATFORMS ?=
.PHONY: docker-buildx
docker-buildx: ## Build and push the manager image for every platform supported by the pinned Go builder.
	- $(CONTAINER_TOOL) buildx create --name flareway-builder
	$(CONTAINER_TOOL) buildx use flareway-builder
	@platforms="$(PLATFORMS)"; \
	if [[ -z "$${platforms}" ]]; then \
		platforms="$$(CONTAINER_TOOL="$(CONTAINER_TOOL)" python3 hack/release-platforms.py)"; \
	fi; \
	$(CONTAINER_TOOL) buildx build --push --platform="$${platforms}" --tag ${IMG} .
	- $(CONTAINER_TOOL) buildx rm flareway-builder

.PHONY: build-installer
build-installer: manifests generate kustomize ## Generate a consolidated YAML with CRDs and deployment.
	mkdir -p dist
	cd config/manager && "$(KUSTOMIZE)" edit set image controller=${IMG}
	"$(KUSTOMIZE)" build config/default > dist/install.yaml

##@ Deployment

ifndef ignore-not-found
  ignore-not-found = false
endif

.PHONY: install
install: manifests kustomize ## Install CRDs into the K8s cluster specified in ~/.kube/config.
	@out="$$( "$(KUSTOMIZE)" build config/crd 2>/dev/null || true )"; \
	if [ -n "$$out" ]; then echo "$$out" | "$(KUBECTL)" apply -f -; else echo "No CRDs to install; skipping."; fi

.PHONY: uninstall
uninstall: manifests kustomize ## Uninstall CRDs from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	@out="$$( "$(KUSTOMIZE)" build config/crd 2>/dev/null || true )"; \
	if [ -n "$$out" ]; then echo "$$out" | "$(KUBECTL)" delete --ignore-not-found=$(ignore-not-found) -f -; else echo "No CRDs to delete; skipping."; fi

.PHONY: deploy
deploy: manifests kustomize ## Deploy controller to the K8s cluster specified in ~/.kube/config.
	cd config/manager && "$(KUSTOMIZE)" edit set image controller=${IMG}
	"$(KUSTOMIZE)" build config/default | "$(KUBECTL)" apply -f -

.PHONY: undeploy
undeploy: kustomize ## Undeploy controller from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	"$(KUSTOMIZE)" build config/default | "$(KUBECTL)" delete --ignore-not-found=$(ignore-not-found) -f -

##@ Dependencies

## Location to install dependencies to
$(LOCALBIN):
	mkdir -p "$(LOCALBIN)"

## Tool Binaries
KUBECTL ?= kubectl
KIND ?= kind
KIND_LOCAL ?= $(LOCALBIN)/kind
KUSTOMIZE ?= $(LOCALBIN)/kustomize
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen
ENVTEST ?= $(LOCALBIN)/setup-envtest
GOLANGCI_LINT = $(LOCALBIN)/golangci-lint
KO ?= $(LOCALBIN)/ko
HELM ?= $(LOCALBIN)/helm
COSIGN ?= $(LOCALBIN)/cosign
CLOUD_PROVIDER_KIND ?= $(LOCALBIN)/cloud-provider-kind

## Tool Versions
KUSTOMIZE_VERSION ?= v5.8.1
CONTROLLER_TOOLS_VERSION ?= v0.22.0
ENVTEST_K8S_VERSION ?= 1.35.0
GOLANGCI_LINT_VERSION ?= v2.13.2
KIND_VERSION ?= v0.33.0
GATEWAY_API_VERSION ?= v1.6.2
KO_VERSION ?= v0.19.1
COSIGN_VERSION ?= v2.6.5
CLOUD_PROVIDER_KIND_VERSION ?= v0.11.1
HELM_VERSION ?= v4.3.0
#ENVTEST_VERSION is the controller-runtime version to use for setup-envtest, derived from go.mod
ENVTEST_VERSION ?= $(shell v='$(call gomodver,sigs.k8s.io/controller-runtime)'; \
  [ -n "$$v" ] || { echo "Set ENVTEST_VERSION manually (controller-runtime replace has no tag)" >&2; exit 1; }; \
  printf '%s\n' "$$v")

.PHONY: kustomize
kustomize: $(KUSTOMIZE) ## Download kustomize locally if necessary.
$(KUSTOMIZE): $(LOCALBIN)
	$(call go-install-tool,$(KUSTOMIZE),sigs.k8s.io/kustomize/kustomize/v5,$(KUSTOMIZE_VERSION))

.PHONY: controller-gen
controller-gen: $(CONTROLLER_GEN) ## Download controller-gen locally if necessary.
$(CONTROLLER_GEN): $(LOCALBIN)
	$(call go-install-tool,$(CONTROLLER_GEN),sigs.k8s.io/controller-tools/cmd/controller-gen,$(CONTROLLER_TOOLS_VERSION))

.PHONY: kind
kind: $(KIND_LOCAL) ## Download Kind locally if necessary.
$(KIND_LOCAL): $(LOCALBIN)
	$(call go-install-tool,$(KIND_LOCAL),sigs.k8s.io/kind,$(KIND_VERSION))

.PHONY: ko
ko: $(KO) ## Download ko locally if necessary.
$(KO): $(LOCALBIN)
	$(call go-install-tool,$(KO),github.com/google/ko,$(KO_VERSION))

.PHONY: helm
helm: $(HELM) ## Download Helm locally if necessary.
$(HELM): $(LOCALBIN)
	$(call go-install-tool,$(HELM),helm.sh/helm/v4/cmd/helm,$(HELM_VERSION))

.PHONY: cosign
cosign: $(COSIGN) ## Download cosign locally if necessary.
$(COSIGN): $(LOCALBIN)
	$(call go-install-tool,$(COSIGN),github.com/sigstore/cosign/v2/cmd/cosign,$(COSIGN_VERSION))

.PHONY: cloud-provider-kind
cloud-provider-kind: $(CLOUD_PROVIDER_KIND) ## Download cloud-provider-kind locally if necessary.
$(CLOUD_PROVIDER_KIND): $(LOCALBIN)
	$(call go-install-tool,$(CLOUD_PROVIDER_KIND),sigs.k8s.io/cloud-provider-kind,$(CLOUD_PROVIDER_KIND_VERSION))

.PHONY: setup-envtest
setup-envtest: envtest ## Download the binaries required for ENVTEST in the local bin directory.
	@echo "Setting up envtest binaries for Kubernetes version $(ENVTEST_K8S_VERSION)..."
	@"$(ENVTEST)" use $(ENVTEST_K8S_VERSION) --bin-dir "$(LOCALBIN)" -p path || { \
		echo "Error: Failed to set up envtest binaries for version $(ENVTEST_K8S_VERSION)."; \
		exit 1; \
	}

.PHONY: envtest
envtest: $(ENVTEST) ## Download setup-envtest locally if necessary.
$(ENVTEST): $(LOCALBIN)
	$(call go-install-tool,$(ENVTEST),sigs.k8s.io/controller-runtime/tools/setup-envtest,$(ENVTEST_VERSION))

.PHONY: golangci-lint
golangci-lint: $(GOLANGCI_LINT) ## Download golangci-lint locally if necessary.
$(GOLANGCI_LINT): $(LOCALBIN)
	$(call go-install-tool,$(GOLANGCI_LINT),github.com/golangci/golangci-lint/v2/cmd/golangci-lint,$(GOLANGCI_LINT_VERSION))
	@test -f .custom-gcl.yml && { \
		echo "Building custom golangci-lint with plugins..." && \
		GOTOOLCHAIN=go1.27.1 $(GOLANGCI_LINT) custom --destination $(LOCALBIN) --name golangci-lint-custom && \
		mv -f $(LOCALBIN)/golangci-lint-custom $(GOLANGCI_LINT); \
	} || true

# go-install-tool will 'go install' any package with custom target and name of binary, if it doesn't exist
# $1 - target path with name of binary
# $2 - package url which can be installed
# $3 - specific version of package
define go-install-tool
@[ -f "$(1)-$(3)" ] && [ "$$(readlink -- "$(1)" 2>/dev/null)" = "$(1)-$(3)" ] || { \
set -e; \
package=$(2)@$(3) ;\
echo "Downloading $${package}" ;\
rm -f "$(1)" ;\
GOTOOLCHAIN=go1.27.1 GOBIN="$(LOCALBIN)" go install $${package} ;\
mv "$(LOCALBIN)/$$(basename "$(1)")" "$(1)-$(3)" ;\
} ;\
ln -sf "$$(realpath "$(1)-$(3)")" "$(1)"
endef

define gomodver
$(shell go list -m -f '{{if .Replace}}{{.Replace.Version}}{{else}}{{.Version}}{{end}}' $(1) 2>/dev/null)
endef
