# ═══════════════════════════════════════════════════════════════
# Trust Kernel v1 — Minimal Container Image
#
# Multi-stage build:
#   Stage 1: Rust build (heavy, discarded)
#   Stage 2: Distroless runtime (minimal attack surface)
#
# Target: <20MB final image, <5ms startup overhead
# ═══════════════════════════════════════════════════════════════

# ── Stage 1: Build ──
FROM rust:1.77-slim-bookworm AS builder

WORKDIR /build

# Copy only what's needed for dependency caching
COPY Cargo.toml ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs && \
    cargo build --release 2>/dev/null || true && \
    rm -rf src

# Copy actual source
COPY src/ src/
COPY benches/ benches/

# Build release binary with full optimisations
RUN cargo build --release --bin tibet-airlock && \
    strip /build/target/release/tibet-airlock

# ── Stage 2: Runtime ──
# Using distroless for minimal attack surface (no shell, no package manager)
FROM gcr.io/distroless/cc-debian12:nonroot

LABEL org.opencontainers.image.title="trust-kernel"
LABEL org.opencontainers.image.description="TIBET Trust Kernel — dual-kernel cryptographic sandbox"
LABEL org.opencontainers.image.vendor="Humotica"
LABEL org.opencontainers.image.version="1.0.0"

# Copy binary
COPY --from=builder /build/target/release/tibet-airlock /usr/local/bin/trust-kernel

# Trust Kernel listens on 4430 (MUX)
EXPOSE 4430

# Health check endpoint would be on this port
EXPOSE 4431

# Environment
ENV TRUST_KERNEL_PROFILE=balanced
ENV RUST_LOG=info

# Run as non-root (UID 65534 = nobody in distroless)
USER nonroot

ENTRYPOINT ["/usr/local/bin/trust-kernel"]
