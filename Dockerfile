# syntax=docker/dockerfile:1@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32

ARG GO_IMAGE=docker.io/library/golang:1.27.1-bookworm@sha256:648f440f42a0958804efb24df176f806f9d353b41f1c0627f666428e40310f6b
ARG SOURCE=https://github.com/isac322/flareway
ARG VERSION
ARG REVISION
ARG CREATED

FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build

ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT

WORKDIR /workspace

COPY go.mod go.sum ./
RUN --mount=type=cache,id=flareway-gomod,target=/go/pkg/mod,sharing=locked \
    go mod download

COPY cmd/ cmd/
COPY api/ api/
COPY internal/ internal/

RUN --mount=type=cache,id=flareway-gomod,target=/go/pkg/mod,sharing=locked \
    --mount=type=cache,id=flareway-gobuild-${TARGETOS}-${TARGETARCH}-${TARGETVARIANT},target=/root/.cache/go-build,sharing=locked \
    set -eu; \
    if [ "${TARGETARCH}" = "arm" ] && [ -n "${TARGETVARIANT}" ]; then \
      export GOARM="${TARGETVARIANT#v}"; \
    fi; \
    CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
    go build \
      -mod=readonly \
      -trimpath \
      -buildvcs=false \
      -tags=netgo,osusergo \
      -ldflags="-s -w -buildid=" \
      -o /manager \
      ./cmd

FROM scratch

ARG SOURCE
ARG VERSION
ARG REVISION
ARG CREATED

LABEL org.opencontainers.image.title="Flareway" \
      org.opencontainers.image.description="Kubernetes operator for Cloudflare connectivity and Zero Trust resources" \
      org.opencontainers.image.source="${SOURCE}" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.licenses="Apache-2.0"

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /manager /manager

USER 65532:65532

ENTRYPOINT ["/manager"]
