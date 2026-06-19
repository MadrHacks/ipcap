# Builds a single static ipcap binary (no libpcap/cgo) used for both the
# collector container and as the artifact pushed to the vulnbox agent.
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-X main.version=${VERSION} -s -w" \
    -o /ipcap ./cmd/ipcap

# Collector image: needs ssh + sshpass to drain the vulnbox agent (mirrors the
# trafficsync wiring: creds from /config/vulnbox.yml).
FROM alpine:3.20
RUN apk add --no-cache openssh-client sshpass ca-certificates
COPY --from=build /ipcap /usr/local/bin/ipcap
ENTRYPOINT ["/usr/local/bin/ipcap"]
CMD ["collector"]
