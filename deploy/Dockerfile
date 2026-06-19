# Builds a single static ipcap binary (no libpcap/cgo) for the collector image.
# Cross-compile on the native build platform targeting TARGETARCH so multi-arch
# CI builds never emulate the Go toolchain.
FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG TARGETARCH
RUN CGO_ENABLED=0 GOARCH=$TARGETARCH go build -trimpath \
    -ldflags "-X main.version=${VERSION} -s -w" \
    -o /ipcap ./cmd/ipcap

# Collector image: drains the vulnbox agent over Noise (no ssh, no sshpass).
FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /ipcap /usr/local/bin/ipcap
ENTRYPOINT ["/usr/local/bin/ipcap"]
CMD ["collector"]
