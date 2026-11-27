# syntax=docker/dockerfile:1

FROM rust:1-bookworm AS builder

WORKDIR /src

# Cache dependency compilation first
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && echo 'fn main() {}' > src/main.rs && echo '' > src/lib.rs \
    && cargo build --release --locked \
    && rm -rf src

# Copy full source and build release binary (optional version override from release tag)
ARG RUSTBAN_VERSION=""
ENV RUSTBAN_VERSION=${RUSTBAN_VERSION}
COPY src ./src
RUN touch src/main.rs src/lib.rs && cargo build --release --locked

# Test stage: runs full unit/integration/exploit test suite in release mode inside Docker
FROM builder AS tester
COPY tests ./tests
COPY rustban.toml.example ./rustban.toml.example
RUN cargo test --release --locked

# Cross-compilation stage: builds Linux x86_64/aarch64 x gnu/musl release binaries on ubuntu-latest
FROM rust:1-bookworm AS cross-builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc-aarch64-linux-gnu libc6-dev-arm64-cross \
    && rm -rf /var/lib/apt/lists/* \
    && rustup target add \
        x86_64-unknown-linux-gnu \
        x86_64-unknown-linux-musl \
        aarch64-unknown-linux-gnu \
        aarch64-unknown-linux-musl

ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="-C target-feature=+crt-static -C link-self-contained=yes" \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="-C target-feature=+crt-static -C link-self-contained=yes"

WORKDIR /src

COPY Cargo.toml Cargo.lock ./
COPY src ./src

ARG RUSTBAN_VERSION=""
ENV RUSTBAN_VERSION=${RUSTBAN_VERSION}
ARG TARGETS="x86_64-unknown-linux-gnu x86_64-unknown-linux-musl aarch64-unknown-linux-gnu aarch64-unknown-linux-musl"

RUN mkdir -p /out && \
    for target in ${TARGETS}; do \
      echo "==> Building release binary for ${target}..."; \
      cargo build --release --locked --target "${target}"; \
      mkdir -p "/out/${target}"; \
      cp "/src/target/${target}/release/rustban" "/out/${target}/rustban"; \
      chmod 0755 "/out/${target}/rustban"; \
    done

# Minimal runtime image with nftables
FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends nftables ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/rustban /usr/local/bin/rustban
COPY rustban.toml.example /etc/rustban/rustban.toml.example

ENTRYPOINT ["/usr/local/bin/rustban"]
CMD ["run", "-c", "/etc/rustban/rustban.toml"]

# E2E harness image (adds python3 only for the local test-docker.sh TCP responder)
FROM runtime AS e2e

RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 \
    && rm -rf /var/lib/apt/lists/*
