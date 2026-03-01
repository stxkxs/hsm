# =============================================================================
# HSM Server Multi-Stage Dockerfile
# =============================================================================
# Build: docker build -t hsm-server .
# Run:   docker run -p 8443:8443 -p 9090:9090 hsm-server
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Build
# -----------------------------------------------------------------------------
FROM rust:1.84-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    protobuf-compiler \
    libz3-dev \
    libclang-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy workspace manifests first for layer caching
COPY Cargo.toml Cargo.lock ./
COPY patches/ patches/

# Copy all crate manifests (for dependency resolution)
COPY crates/crypto-engine/Cargo.toml crates/crypto-engine/Cargo.toml
COPY crates/key-manager/Cargo.toml crates/key-manager/Cargo.toml
COPY crates/auth/Cargo.toml crates/auth/Cargo.toml
COPY crates/grpc-api/Cargo.toml crates/grpc-api/Cargo.toml
COPY crates/rest-api/Cargo.toml crates/rest-api/Cargo.toml
COPY crates/audit/Cargo.toml crates/audit/Cargo.toml
COPY crates/metrics/Cargo.toml crates/metrics/Cargo.toml
COPY crates/storage/Cargo.toml crates/storage/Cargo.toml
COPY crates/backup/Cargo.toml crates/backup/Cargo.toml
COPY crates/config/Cargo.toml crates/config/Cargo.toml
COPY crates/hsm-server/Cargo.toml crates/hsm-server/Cargo.toml
COPY crates/verification/Cargo.toml crates/verification/Cargo.toml
COPY crates/zk-proofs/Cargo.toml crates/zk-proofs/Cargo.toml
COPY crates/hardware-backend/Cargo.toml crates/hardware-backend/Cargo.toml
COPY crates/pkcs11-bridge/Cargo.toml crates/pkcs11-bridge/Cargo.toml
COPY crates/secrets/Cargo.toml crates/secrets/Cargo.toml
COPY crates/kmip-server/Cargo.toml crates/kmip-server/Cargo.toml
COPY crates/blockchain/Cargo.toml crates/blockchain/Cargo.toml
COPY crates/webhooks/Cargo.toml crates/webhooks/Cargo.toml
COPY crates/validator/Cargo.toml crates/validator/Cargo.toml
COPY crates/wasm-policy/Cargo.toml crates/wasm-policy/Cargo.toml
COPY crates/cluster/Cargo.toml crates/cluster/Cargo.toml
COPY crates/bridge-monitor/Cargo.toml crates/bridge-monitor/Cargo.toml

# Create dummy source files for dependency caching
RUN for dir in crates/*/; do \
      mkdir -p "$dir/src"; \
      echo "" > "$dir/src/lib.rs"; \
    done && \
    mkdir -p crates/hsm-server/src && \
    echo "fn main() {}" > crates/hsm-server/src/main.rs

# Copy proto files (needed for grpc-api build)
COPY crates/grpc-api/proto/ crates/grpc-api/proto/
COPY crates/grpc-api/build.rs crates/grpc-api/build.rs

# Build dependencies only (cached layer)
RUN cargo build --release --bin hsm-server 2>/dev/null || true

# Copy actual source code
COPY crates/ crates/

# Build the real binary
RUN cargo build --release --bin hsm-server

# -----------------------------------------------------------------------------
# Stage 2: Runtime (minimal image)
# -----------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

# Install minimal runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libz3-4 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd --gid 1000 hsm && \
    useradd --uid 1000 --gid hsm --shell /bin/false --create-home hsm

# Create data directories
RUN mkdir -p /data/hsm /etc/hsm && \
    chown -R hsm:hsm /data/hsm /etc/hsm

# Copy the binary
COPY --from=builder /build/target/release/hsm-server /usr/local/bin/hsm-server

# Use non-root user
USER hsm

# Expose ports
# 8443: REST API (HTTPS)
# 9090: Prometheus metrics
EXPOSE 8443 9090

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/hsm-server", "--help"]

# Default configuration via environment variables
ENV HSM_REST_PORT=8443 \
    HSM_METRICS_PORT=9090 \
    HSM_LOG_LEVEL=info \
    HSM_JSON_LOGS=true

ENTRYPOINT ["/usr/local/bin/hsm-server"]
