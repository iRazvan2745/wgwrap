# The wgwrap-init image: nothing but the static entrypoint binary.
# Cross-compiles on the build platform, so multi-arch builds need no QEMU.
# Pinned by digest; bump together with the go version in mise.toml.
ARG GO_IMAGE=golang:1.26.11-alpine@sha256:ecb67f987aa1a57794c91d19ade7ae0209f2f0f5496aaef9e6ae85ddf92d02ab
FROM --platform=$BUILDPLATFORM $GO_IMAGE AS build
ARG TARGETOS TARGETARCH TARGETVARIANT VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN GOARM=${TARGETVARIANT#v} CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /wgwrap-init ./cmd/wgwrap-init

FROM scratch
COPY --from=build /wgwrap-init /wgwrap-init
ENTRYPOINT ["/wgwrap-init"]
