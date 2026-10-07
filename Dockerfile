# Multi-stage build for betterproxy
FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN VERSION=$(cat VERSION) && BUILD_TIME=$(date -u "+%Y-%m-%d_%H:%M:%S") && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -X main.Version=$VERSION -X main.BuildTime=$BUILD_TIME -X main.GoVersion=$(go version | awk '{print $3}')" \
    -o /build/bin/betterproxy ./cmd/betterproxy

# Final stage
FROM alpine:latest

RUN apk add --no-cache ca-certificates tzdata netcat-openbsd

RUN addgroup -g 1000 betterproxy && \
    adduser -D -u 1000 -G betterproxy betterproxy

WORKDIR /opt/betterproxy

COPY --from=builder /build/bin/betterproxy /usr/local/bin/

RUN mkdir -p /opt/betterproxy/policies && \
    chown -R betterproxy:betterproxy /opt/betterproxy

USER betterproxy

EXPOSE 3025 3587 50051

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD nc -z 127.0.0.1 3025 || exit 1

ENTRYPOINT ["/usr/local/bin/betterproxy"]
CMD ["proxy", "--help"]
