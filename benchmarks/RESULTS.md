# Benchmark Results: `rustban` vs `fail2ban`

Reproducible head-to-head benchmark comparing **`rustban`** (release build compiled inside Docker) against official Debian Bookworm **`fail2ban`** (`nftables` all-ports drop action + `pyinotify` backend).

> Re-run anytime with `./scripts/bench-docker.sh`. Raw machine-readable metrics are stored in [`results.json`](./results.json).

## Test Environment & Fairness Controls

| Property | Value |
|---|---|
| **Date (UTC)** | `2026-11-27T10:48:05Z` |
| **Host CPU** | `AMD EPYC 9V74 80-Core Processor` (4 vCPUs, `x86_64`) |
| **Linux Kernel** | `7.0.0-1020-azure` |
| **Container Runtime** | Docker `29.4.2` (`--cap-add=NET_ADMIN`, `debian:bookworm-slim`) |
| **`rustban`** | `rustban 0.2.0` (`nftables v1.0.6 (Lester Gooch #5)`) |
| **`fail2ban`** | `Fail2Ban v1.0.2 (Python 3.11.2)` (`nftables v1.0.6 (Lester Gooch #5)`) |

**Apples-to-apples controls**:
- Both run in identical isolated `debian:bookworm-slim` containers with the exact same `nftables` (`1.0.6`) userspace and host Linux kernel.
- Both use **inotify** file watching (`notify` in `rustban`, `backend = pyinotify` in `fail2ban` — not polling).
- Both enforce **all-port `nftables` `drop`** rules (`table inet rustban` vs `banaction = nftables[type=allports, blocktype=drop]`).
- Both use the **exact same single SSH `Failed password` regex** (`usedns = no` for `fail2ban`, stripped single-pattern custom filter so `fail2ban` is not penalized by unused default SSH regexes).
- Both are warmed up with 1 initial ban before timed bursts so `fail2ban`'s `actionstart_on_demand` table initialization is excluded from steady-state latency and burst timings.

---

## Summary Comparison

| Benchmark | Metric | `rustban` | `fail2ban` | Advantage (`rustban` vs `fail2ban`) |
|---|---|---:|---:|---|
| **Disk / Binary** | Binary vs package footprint | 2.26 MiB | 22.84 MiB | **10.1x smaller** |
| **Container Image** | Minimal runtime Docker image | 31.71 MiB | 43.37 MiB | **1.4x smaller** |
| **Cold Startup** | Median boot-to-ready (5 runs) | 15.48 ms | 195.17 ms | **12.6x faster / lower** |
| **Idle Memory** | Steady RSS (`VmRSS`) | 4.28 MiB | 17.64 MiB | **4.1x less RAM** |
| **Single-IP Ban Latency** | p50 detection → kernel `nft` (20 trials) | 11.84 ms | 155.25 ms | **13.1x faster / lower** |
| **Single-IP Ban Latency** | p95 detection → kernel `nft` (20 trials) | 13.92 ms | 156.79 ms | **11.3x faster / lower** |
| **100k Noise Ingestion** | Live throughput | 2,360,888 lines/s | 60,507 lines/s | **39.0x higher** |
| **100k Noise Ingestion** | Wall time / Peak RSS | 0.042s / 4.25 MiB | 1.653s / 19.44 MiB | **39.0x faster / lower** |
| **200-Ban Attack Burst** | Wall time (200 real `nft` bans + 5k scanners + 10k noise) | 0.030s (6708.5 bans/s) | 1.342s (149.1 bans/s) | **45.0x faster / lower** |
| **200-Ban Attack Burst** | Total CPU (daemon + `nft` children) | 20 ms | 1550 ms | **77.5x faster / lower** |
| **200-Ban Attack Burst** | Peak RSS (`VmHWM`) | 6.19 MiB | 26.04 MiB | **4.2x less RAM** |
| **CLI Status (201 bans)** | Median `status` query latency (10 runs) | 4.95 ms | 44.19 ms | **8.9x faster / lower** |
| **50k Spoofed-IP Flood** | Wall time (50k unique IPs × 1 failure) | 0.190s (262,898 IPs/s) | 2.327s (21,489 IPs/s) | **12.2x faster / lower** |
| **50k Spoofed-IP Flood** | Peak RSS (`VmHWM`) | 13.26 MiB | 69.96 MiB | **5.3x less RAM** |
| **100-Ban Expiration (5s TTL)** | Userspace + child CPU during expiration | 0.0 ms | 480.0 ms | ∞ (0 ms) |
| **Offline Regex (100k lines)** | `rustban test` vs `fail2ban-regex` (10k matches) | 0.041s (2,421,308 lines/s) | 1.525s (65,574 lines/s) | **36.9x higher** |

---

## Detailed Breakdown

### 1. Startup & Idle Footprint
- **`rustban`**: `2.26 MiB` stripped static-ish Rust binary, `15.48 ms` median cold start, `4.28 MiB` RSS (`3.59 MiB` PSS), `3` OS threads.
- **`fail2ban`**: `22.84 MiB` installed package footprint (fail2ban + Python 3.11 + pyinotify), `195.17 ms` median cold start, `17.64 MiB` RSS (`14.99 MiB` PSS), `5` OS threads.

### 2. Single-IP Detection-to-Kernel-Ban Latency (20 live trials)
Time from writing 3 matching auth-failure log lines until the attacker IP is actively enforced inside the Linux kernel `nftables` set:
- **`rustban`**: min `5.33 ms`, p50 `11.84 ms`, mean `10.38 ms`, p95 `13.92 ms`, max `15.93 ms`.
- **`fail2ban`**: min `153.74 ms`, p50 `155.25 ms`, mean `167.83 ms`, p95 `156.79 ms`, max `406.14 ms`.

### 3. High-Volume Noise Log Ingestion (100,000 non-matching lines + 1 sentinel ban)
- **`rustban`**: `0.042s` (`2,360,888 lines/s`), daemon CPU `60.0 ms`, child CPU `0.0 ms`, peak RSS `4.25 MiB`.
- **`fail2ban`**: `1.653s` (`60,507 lines/s`), daemon CPU `1400.0 ms`, child CPU `0.0 ms`, peak RSS `19.44 MiB`.

### 4. Distributed Attack Burst (200 real `nftables` bans + 5,000 scanners + 10,000 noise lines)
- **`rustban`**: `0.030s` (`6708.5 bans/s`), daemon CPU `20.0 ms`, child (`nft`) CPU `0.0 ms`, total CPU `20.0 ms`, peak RSS `6.19 MiB`, steady RSS `6.19 MiB`.
- **`fail2ban`**: `1.342s` (`149.1 bans/s`), daemon CPU `790.0 ms`, child (`sh`/`nft`) CPU `760.0 ms`, total CPU `1550.0 ms`, peak RSS `26.04 MiB`, steady RSS `26.04 MiB`.
- *Note*: `rustban` drains queued events and coalesces concurrent bans into atomic batched `nft -f -` transactions, amortizing Linux kernel `nf_tables` netlink commit overhead across bursts while preserving immediate single-IP flush latency.

### 5. High-Cardinality Spoofed-IP Flood (50,000 unique IPs × 1 failure + 1 sentinel ban)
Tests memory bounding and tracking overhead under distributed botnet credential stuffing where IPs do not reach `max_retries`:
- **`rustban`**: `0.190s` (`262,898 unique IPs/s`), daemon CPU `250.0 ms`, peak RSS `13.26 MiB`.
- **`fail2ban`**: `2.327s` (`21,489 unique IPs/s`), daemon CPU `1680.0 ms`, peak RSS `69.96 MiB`.

### 6. Ban Expiration Overhead (100 active bans × 5s TTL)
Directly tests `rustban`'s core thesis — offloading ban expiration to the Linux kernel via `nftables` timeout sets:
- **`rustban`**: drained in `5.04s` with **`0.0 ms` daemon CPU** and **`0.0 ms` child (`nft`) CPU** (zero userspace wakeups, zero `nft delete element` subprocesses).
- **`fail2ban`**: drained in `5.12s` with **`130.0 ms` daemon CPU** and **`350.0 ms` child (`sh`/`nft`) CPU** (100 userspace unban timer wakeups + 100 `nft delete element` subprocesses + SQLite updates).

### 7. Offline Regex Engine (`rustban test` vs `fail2ban-regex`, 100k lines / 10k matches)
- **`rustban test`**: median `0.041s` (`2,421,308 lines/s`, runs: `[0.0413, 0.0418, 0.0408]`).
- **`fail2ban-regex`**: median `1.525s` (`65,574 lines/s`, runs: `[1.5345, 1.525, 1.5169]`).
