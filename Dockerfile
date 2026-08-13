# Multi-stage Dockerfile for the Adrian `adrian-cli` binary.
#
# The Rust workspace lives under the `rust/` subdirectory, so all `cargo`
# invocations use `--manifest-path rust/Cargo.toml`. See CONTRIBUTING.md for
# local build instructions.

# syntax=docker/dockerfile:1.6

# ---- Build stage -------------------------------------------------------------
FROM rust:1.97-slim AS builder

# Build dependencies for crates that link against OpenSSL (e.g. git2, ldap3,
# rustls is preferred but some transitive native deps still need pkg-config).
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        pkg-config \
        libssl-dev \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy only the workspace manifest + lockfile first so that the dependency
# download/build step is cached across source-only changes.
COPY rust/Cargo.toml rust/Cargo.lock ./rust/

# Copy the full workspace source.
COPY rust/crates ./rust/crates

# Build the release binary. `--release -p adrian-cli` builds just the CLI and
# its dependency closure (and any `[[bin]]` target it exposes).
RUN cd rust && cargo build --release -p adrian-cli

# ---- Runtime stage -----------------------------------------------------------
FROM debian:bookworm-slim

# Minimal runtime: OpenSSL 3 libs (for any native crypto the release binary
# links against) plus CA roots for outbound TLS.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libssl3 \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Non-root user for the entrypoint binary.
RUN useradd --system --no-create-home --shell /usr/sbin/nologin adrian

COPY --from=builder /app/rust/target/release/adrian /usr/local/bin/adrian

USER adrian

ENTRYPOINT ["adrian"]
CMD ["--help"]
