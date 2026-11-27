# Benchmark Results: `rustban` vs `fail2ban`

Reproducible head-to-head benchmark comparing **`rustban`** (release build compiled inside Docker) against official Debian Bookworm **`fail2ban`** (`nftables` all-ports drop action + `pyinotify` backend).

> Re-run anytime with `./scripts/bench-docker.sh`. Raw machine-readable metrics are stored in [`results.json`](./results.json).

## Test Environment & Fairness Controls

| Property | Value |
|---|---|
| **Date (UTC)** | `2026-11-27T11:28:44Z` |
| **Host CPU** | `AMD EPYC 7763 64-Core Processor` (4 vCPUs, `x86_64`) |
| **Linux Kernel** | `7.0.0-1020-azure` |
| **Container Runtime** | Docker `29.4.2` (`--cap-add=NET_ADMIN`, `debian:bookworm-slim`) |
| **`rustban`** | `rustban 0.3.0` (`nftables v1.0.6 (Lester Gooch #5)`) |
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
| **Disk / Binary** | Binary vs package footprint | 2.36 MiB | 22.84 MiB | **9.7x smaller** |
| **Container Image** | Minimal runtime Docker image | 5.63 MiB | 43.37 MiB | **7.7x smaller** |
| **Cold Startup** | Median boot-to-ready (5 runs) | 14.67 ms | 220.47 ms | **15.0x faster / lower** |
| **Idle Memory** | Steady RSS (`VmRSS`) | 2.48 MiB | 17.57 MiB | **7.1x less RAM** |
| **Single-IP Ban Latency** | p50 detection → kernel `nft` (20 trials) | 10.82 ms | 156.19 ms | **14.4x faster / lower** |
| **Single-IP Ban Latency** | p95 detection → kernel `nft` (20 trials) | 12.11 ms | 158.29 ms | **13.1x faster / lower** |
| **100k Noise Ingestion** | Live throughput | 1,730,626 lines/s | 48,021 lines/s | **36.0x higher** |
| **100k Noise Ingestion** | Wall time / Peak RSS | 0.058s / 2.60 MiB | 2.082s / 19.36 MiB | **36.0x faster / lower** |
| **200-Ban Attack Burst** | Wall time (200 real `nft` bans + 5k scanners + 10k noise) | 0.046s (4312.7 bans/s) | 1.685s (118.7 bans/s) | **36.3x faster / lower** |
| **200-Ban Attack Burst** | Total CPU (daemon + `nft` children) | 40 ms | 2040 ms | **51.0x faster / lower** |
| **200-Ban Attack Burst** | Peak RSS (`VmHWM`) | 3.91 MiB | 26.22 MiB | **6.7x less RAM** |
| **CLI Status (201 bans)** | Median `status` query latency (10 runs) | 6.4 ms | 53.99 ms | **8.4x faster / lower** |
| **50k Spoofed-IP Flood** | Wall time (50k unique IPs × 1 failure) | 0.339s (147,559 IPs/s) | 3.770s (13,262 IPs/s) | **11.1x faster / lower** |
| **50k Spoofed-IP Flood** | Peak RSS (`VmHWM`) | 11.42 MiB | 69.26 MiB | **6.1x less RAM** |
| **100-Ban Expiration (5s TTL)** | Userspace + child CPU during expiration | 0.0 ms | 560.0 ms | ∞ (0 ms) |
| **Offline Regex (100k lines)** | `rustban test` vs `fail2ban-regex` (10k matches) | 0.052s (1,908,397 lines/s) | 2.407s (41,546 lines/s) | **45.9x higher** |

---

## Detailed Breakdown

### 1. Startup & Idle Footprint
- **`rustban`**: `2.36 MiB` stripped static-ish Rust binary, `14.67 ms` median cold start, `2.48 MiB` RSS (`2.48 MiB` PSS), `3` OS threads.
- **`fail2ban`**: `22.84 MiB` installed package footprint (fail2ban + Python 3.11 + pyinotify), `220.47 ms` median cold start, `17.57 MiB` RSS (`15.01 MiB` PSS), `5` OS threads.

### 2. Single-IP Detection-to-Kernel-Ban Latency (20 live trials)
Time from writing 3 matching auth-failure log lines until the attacker IP is actively enforced inside the Linux kernel `nftables` set:
- **`rustban`**: min `6.83 ms`, p50 `10.82 ms`, mean `10.23 ms`, p95 `12.11 ms`, max `14.75 ms`.
- **`fail2ban`**: min `153.86 ms`, p50 `156.19 ms`, mean `168.6 ms`, p95 `158.29 ms`, max `405.77 ms`.

### 3. High-Volume Noise Log Ingestion (100,000 non-matching lines + 1 sentinel ban)
- **`rustban`**: `0.058s` (`1,730,626 lines/s`), daemon CPU `80.0 ms`, child CPU `0.0 ms`, peak RSS `2.60 MiB`.
- **`fail2ban`**: `2.082s` (`48,021 lines/s`), daemon CPU `2070.0 ms`, child CPU `0.0 ms`, peak RSS `19.36 MiB`.

### 4. Distributed Attack Burst (200 real `nftables` bans + 5,000 scanners + 10,000 noise lines)
- **`rustban`**: `0.046s` (`4312.7 bans/s`), daemon CPU `40.0 ms`, child (`nft`) CPU `0.0 ms`, total CPU `40.0 ms`, peak RSS `3.91 MiB`, steady RSS `3.80 MiB`.
- **`fail2ban`**: `1.685s` (`118.7 bans/s`), daemon CPU `1130.0 ms`, child (`sh`/`nft`) CPU `910.0 ms`, total CPU `2040.0 ms`, peak RSS `26.22 MiB`, steady RSS `26.22 MiB`.
- *Note*: `rustban` drains queued events and coalesces concurrent bans into atomic batched `nft -f -` transactions, amortizing Linux kernel `nf_tables` netlink commit overhead across bursts while preserving immediate single-IP flush latency.

### 5. High-Cardinality Spoofed-IP Flood (50,000 unique IPs × 1 failure + 1 sentinel ban)
Tests memory bounding and tracking overhead under distributed botnet credential stuffing where IPs do not reach `max_retries`:
- **`rustban`**: `0.339s` (`147,559 unique IPs/s`), daemon CPU `450.0 ms`, peak RSS `11.42 MiB`.
- **`fail2ban`**: `3.770s` (`13,262 unique IPs/s`), daemon CPU `3280.0 ms`, peak RSS `69.26 MiB`.

### 6. Ban Expiration Overhead (100 active bans × 5s TTL)
Directly tests `rustban`'s core thesis — offloading ban expiration to the Linux kernel via `nftables` timeout sets:
- **`rustban`**: drained in `5.00s` with **`0.0 ms` daemon CPU** and **`0.0 ms` child (`nft`) CPU** (zero userspace wakeups, zero `nft delete element` subprocesses).
- **`fail2ban`**: drained in `5.62s` with **`160.0 ms` daemon CPU** and **`400.0 ms` child (`sh`/`nft`) CPU** (100 userspace unban timer wakeups + 100 `nft delete element` subprocesses + SQLite updates).

### 7. Offline Regex Engine (`rustban test` vs `fail2ban-regex`, 100k lines / 10k matches)
- **`rustban test`**: median `0.052s` (`1,908,397 lines/s`, runs: `[0.0526, 0.0522, 0.0524]`).
- **`fail2ban-regex`**: median `2.407s` (`41,546 lines/s`, runs: `[2.407, 2.368, 2.4241]`).
