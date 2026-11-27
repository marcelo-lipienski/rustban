# syntax=docker/dockerfile:1

FROM rust:1-bookworm AS builder

ENV CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="-C target-feature=+crt-static -C link-self-contained=yes" \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="-C target-feature=+crt-static -C link-self-contained=yes"

RUN MUSL_TARGET="$(uname -m)-unknown-linux-musl" \
    && rustup target add "${MUSL_TARGET}" \
    && echo "${MUSL_TARGET}" > /tmp/musl-target

WORKDIR /src

# Cache dependency compilation first
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && echo 'fn main() {}' > src/main.rs && echo '' > src/lib.rs \
    && cargo build --release --locked --target "$(cat /tmp/musl-target)" \
    && rm -rf src

# Copy full source and build fully static musl release binary (optional version override from release tag)
ARG RUSTBAN_VERSION=""
ENV RUSTBAN_VERSION=${RUSTBAN_VERSION}
COPY src ./src
RUN MUSL_TARGET="$(cat /tmp/musl-target)" \
    && touch src/main.rs src/lib.rs \
    && cargo build --release --locked --target "${MUSL_TARGET}" \
    && cp "/src/target/${MUSL_TARGET}/release/rustban" /usr/local/bin/rustban \
    && chmod 0755 /usr/local/bin/rustban

# Test stage: runs full unit/integration/exploit test suite in release mode on the static musl target
FROM builder AS tester
COPY tests ./tests
COPY rustban.toml.example ./rustban.toml.example
RUN cargo test --release --locked --target "$(cat /tmp/musl-target)"

# Cross-compilation stage: builds fully static Linux musl release binaries (x86_64 & aarch64)
FROM rust:1-bookworm AS cross-builder

RUN rustup target add \
        x86_64-unknown-linux-musl \
        aarch64-unknown-linux-musl

ENV CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="-C target-feature=+crt-static -C link-self-contained=yes" \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="-C target-feature=+crt-static -C link-self-contained=yes"

WORKDIR /src

COPY Cargo.toml Cargo.lock ./
COPY src ./src

ARG RUSTBAN_VERSION=""
ENV RUSTBAN_VERSION=${RUSTBAN_VERSION}
ARG TARGETS="x86_64-unknown-linux-musl aarch64-unknown-linux-musl"

RUN mkdir -p /out && \
    for target in ${TARGETS}; do \
      echo "==> Building static musl release binary for ${target}..."; \
      cargo build --release --locked --target "${target}"; \
      mkdir -p "/out/${target}"; \
      cp "/src/target/${target}/release/rustban" "/out/${target}/rustban"; \
      chmod 0755 "/out/${target}/rustban"; \
    done

# Minimal Alpine runtime image with nftables (runs the fully static musl binary)
FROM alpine:3.20 AS runtime

RUN apk add --no-cache nftables ca-certificates

COPY --from=builder /usr/local/bin/rustban /usr/local/bin/rustban
COPY rustban.toml.example /etc/rustban/rustban.toml.example

ENTRYPOINT ["/usr/local/bin/rustban"]
CMD ["run", "-c", "/etc/rustban/rustban.toml"]

# E2E & benchmark harness image: stays on debian:bookworm-slim for apples-to-apples nftables comparisons against fail2ban
FROM debian:bookworm-slim AS e2e

RUN apt-get update \
    && apt-get install -y --no-install-recommends nftables ca-certificates python3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/bin/rustban /usr/local/bin/rustban
COPY rustban.toml.example /etc/rustban/rustban.toml.example

ENTRYPOINT ["/usr/local/bin/rustban"]
CMD ["run", "-c", "/etc/rustban/rustban.toml"]
