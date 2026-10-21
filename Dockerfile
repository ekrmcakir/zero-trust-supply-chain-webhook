# Multi-stage zero-trust build
FROM golang:alpine AS builder

WORKDIR /workspace

# Install ca-certificates and git
RUN apk add --no-cache ca-certificates git

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY cmd/ cmd/
COPY pkg/ pkg/

# Compile static binary with optimizations and stripped symbols
ARG VERSION=1.0.0
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w -X main.Version=${VERSION} -X main.GitCommit=${COMMIT} -X main.BuildDate=${BUILD_DATE}" \
    -o /workspace/bin/webhook ./cmd/webhook

# Minimal distroless non-root runtime image
FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /
COPY --from=builder /workspace/bin/webhook /usr/local/bin/webhook
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Run as nonroot user (UID 65532)
USER 65532:65532

EXPOSE 8443 9090

ENTRYPOINT ["/usr/local/bin/webhook"]
