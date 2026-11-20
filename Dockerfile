# The wgwrap-init image: nothing but the static entrypoint binary.
# Cross-compiles on the build platform, so multi-arch builds need no QEMU.
ARG GO_IMAGE=golang:1.26-alpine
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
