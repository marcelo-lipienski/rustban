# rustban

[![CI](https://github.com/marcelo-lipienski/rustban/actions/workflows/ci.yml/badge.svg)](https://github.com/marcelo-lipienski/rustban/actions/workflows/ci.yml)
[![Release](https://github.com/marcelo-lipienski/rustban/actions/workflows/release.yml/badge.svg)](https://github.com/marcelo-lipienski/rustban/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Lightweight Fail2Ban replacement in Rust that offloads ban expiration to Linux `nftables` timeout sets — zero database, zero timers, lockout-proof.

## Design

- **Kernel as the sole active-ban store**: zero SQLite database, zero background unban timers, zero Unix socket IPC, zero async runtime (`tokio`), and zero C FFI dependencies.
- **Ephemeral in-memory failure windows & opt-in escalation**: each jail tracks only unbanned failing IPs inside `find_time` (with O(1) bounded memory caps). Once an IP reaches `max_retries`, `rustban` writes it to `nftables` with `timeout <ban_time>` and immediately forgets it. Optional per-jail progressive escalation (`ban_time_multiplier`, `ban_time_max`, `ban_time_window`) scales repeat offenders without a database and incurs zero overhead when disabled.
- **Lockout-proof `nftables` schema (`table inet rustban`)**:
  - Hooks `prerouting` at `raw` priority (`-300`), dropping offending packets before `conntrack`, severing active TCP sessions immediately, and protecting both host services and Docker/Podman port-forwarded containers.
  - Enforces `ignore_ips` (defaulting to `127.0.0.0/8`, `::1/128`, `fe80::/10`, plus `ignore_self` local interface IPs, with opt-in `ignore_self_refresh` and opt-in `ignore_interfaces`) in both userspace **and** kernel `return` rules evaluated before the drop rules.
  - Uses O(1) timeout hash sets (`banned_v4` `/32` hosts and `banned_v6` `/64` prefixes via `ip6 saddr & ffff:ffff:ffff:ffff:: @banned_v6 drop`) with kernel per-element packet/byte `counter` and jail `comment`.
  - Survives daemon restarts, stops, and live `SIGHUP` config reloads (`table inet rustban` and remaining kernel TTLs stay intact until explicitly cleared with `flush` or `teardown`).
- **Dual log sources & explicit TOML regexes**: tails plain log files (handling inode rotation and `copytruncate`) and `systemd-journald` units/identifiers (`systemd_unit`, `systemd_units`, `syslog_identifier`) with bounded line buffers, matching with Rust's linear-time ReDoS-safe `regex` crate.

## Building (Docker Release Only)

All compilation runs in release mode inside Docker — never locally:

```bash
./scripts/build-docker.sh
```

To extract the compiled native Linux release binary into `./dist/rustban`, or cross-compile all 4 release targets (`x86_64`/`aarch64` × `gnu`/`static musl`):

```bash
./scripts/build-docker.sh --extract
./scripts/build-docker.sh --all-targets
./scripts/build-docker.sh --target aarch64-unknown-linux-musl
```

## Testing Locally Against Docker

Run the full release unit test suite inside Docker **and** a live end-to-end banning test from your host against a running `rustban` container (proving real Linux kernel `nftables` packet drops, per-IP drop counters, automatic kernel timeout unbanning, IPv6 `/64` masking, whitelist protection, restart preservation, and CLI subcommands):

```bash
./scripts/test-docker.sh
```

## Benchmarks & Live Security Comparison (`rustban` vs `fail2ban`)

Reproducible head-to-head Docker benchmarks and live exploit tests comparing `rustban` (release) against Debian Bookworm `fail2ban` (`pyinotify` + `nftables` all-ports `drop` action):

```bash
./scripts/bench-docker.sh             # Performance & resource benchmarks vs fail2ban
./scripts/security-check-docker.sh    # Live 8-vector rustban-only security gate (asserts 8/8 protected)
./scripts/security-compare-docker.sh  # Live 8-vector security comparison vs fail2ban
```

Stored results are published in [`benchmarks/RESULTS.md`](benchmarks/RESULTS.md) ([`results.json`](benchmarks/results.json)) and [`benchmarks/SECURITY_COMPARISON.md`](benchmarks/SECURITY_COMPARISON.md) ([`security_results.json`](benchmarks/security_results.json)):

| Workload | `rustban` | `fail2ban` | Difference |
|---|---:|---:|---|
| Binary / package footprint | 2.13 MiB | 22.84 MiB | **10.7x smaller** |
| Cold startup (median) | 13.37 ms | 185.22 ms | **13.9x faster** |
| Idle RAM (`VmRSS`) | 4.17 MiB | 17.70 MiB | **4.2x less RAM** |
| Single-IP ban latency (p50) | 12.32 ms | 153.11 ms | **12.4x faster** |
| 100k noise log ingestion | 2,753,078 lines/s | 53,209 lines/s | **51.7x faster** |
| 200-ban attack burst (wall / total CPU) | 0.027s (7,477 bans/s) / 20 ms | 1.024s (195 bans/s) / 1,120 ms | **38.3x faster / 56.0x less CPU** |
| 50k spoofed-IP flood (wall / peak RSS) | 0.168s / 13.00 MiB | 2.651s / 69.27 MiB | **15.8x faster / 5.3x less RAM** |
| 100-ban expiration (5s TTL) CPU | 0.0 ms (kernel TTL) | 380.0 ms (100× `nft delete`) | **Zero userspace CPU** |
| Offline regex (100k lines, 10k matches) | 0.043s (2.34M lines/s) | 1.854s (53.9k lines/s) | **43.3x faster** |
| Live 8-vector exploit suite | **8/8 protected** | **3/8 protected** (4 vulnerable, 1 partial) | See [`SECURITY_COMPARISON.md`](benchmarks/SECURITY_COMPARISON.md) |

## CLI Usage

```bash
# Validate configuration, regex safety, CIDRs, and external binaries
rustban check -c /etc/rustban/rustban.toml [--strict]

# Run daemon (--dry-run inspects nft scripts; --log-format json emits NDJSON; SIGHUP reloads live)
rustban run -c /etc/rustban/rustban.toml [--dry-run] [--log-format text|json]

# Inspect active kernel bans, remaining TTLs, and dropped packet counters
rustban status [--json | --prometheus]

# Manually ban / unban an IPv4 address or IPv6 /64 prefix
rustban ban 203.0.113.42 -t 1h -r manual
rustban unban 203.0.113.42

# Clear all active bans or completely remove table inet rustban
rustban flush
rustban teardown

# Validate config and test jail regexes offline against a log file or stdin
rustban test -c /etc/rustban/rustban.toml [--include-disabled] [--strict] /var/log/auth.log
```

## Systemd Deployment

1. Extract the release binary built in Docker and install it:
   ```bash
   ./scripts/build-docker.sh --extract
   sudo install -m 0755 dist/rustban /usr/local/bin/rustban
   sudo install -d /etc/rustban
   sudo install -m 0644 rustban.toml.example /etc/rustban/rustban.toml
   ```
2. Edit `/etc/rustban/rustban.toml`, test your rules with `rustban test`, and enable the hardened non-root service:
   ```bash
   sudo install -m 0644 contrib/rustban.service /etc/systemd/system/rustban.service
   sudo systemctl daemon-reload
   sudo systemctl enable --now rustban
   ```

## License

Licensed under the [MIT License](LICENSE).
