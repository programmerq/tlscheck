# Build stage
FROM golang:1.24.3-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git make

WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags "-X github.com/programmerq/tlscheck/internal/version.Version=${VERSION}" \
    -o tlscheck \
    ./cmd/tlscheck

# Final stage
FROM alpine:latest

# Install ca-certificates for TLS connections
RUN apk --no-cache add ca-certificates

# Create non-root user
RUN addgroup -g 1000 tlscheck && \
    adduser -D -u 1000 -G tlscheck tlscheck

WORKDIR /home/tlscheck

# Copy binary from builder
COPY --from=builder /build/tlscheck /usr/local/bin/tlscheck

# Switch to non-root user
USER tlscheck

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/tlscheck"]
CMD ["--help"]
