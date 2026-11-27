# Contributing to rustban

Thank you for your interest in contributing to `rustban`!

## Guiding Principles

`rustban` intentionally stays small, predictable, and dependency-light:

- **Kernel-owned active bans**: no SQLite/state files, no userspace unban timers, no IPC daemon sockets.
- **No async runtime or C FFI**: synchronous standard library Rust + `nft -f -` atomic transactions.
- **Lockout-proof by default**: host self-IPs and default/configured `ignore_ips` are protected in both userspace and kernel `nftables` whitelist `return` rules.
- **Linear-time regexes only**: all patterns must be safe against ReDoS and anchored cleanly against log-injection spoofing.

## Development Workflow

### Prerequisites

- Docker (with Linux kernel `nftables` support for live E2E tests)
- Rust stable toolchain (optional locally for `cargo fmt` and `cargo clippy`)

### Running Checks

```bash
# Formatting & lints
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings

# Full Docker release build, unit/exploit tests, and live nftables E2E test suite
./scripts/test-docker.sh

# Live 8-vector rustban-only security gate (must pass 8/8)
./scripts/security-check-docker.sh

# Optional: head-to-head benchmarks against fail2ban
./scripts/bench-docker.sh
```

## Pull Requests

1. Fork the repository and create a topic branch from `main`.
2. Keep changes focused and include unit/integration tests (and exploit regression tests for any security-relevant change).
3. Ensure `cargo fmt`, `cargo clippy --all-targets --locked -- -D warnings`, and `./scripts/test-docker.sh` all pass.
4. Open a pull request describing the motivation, changes, and verification performed.
