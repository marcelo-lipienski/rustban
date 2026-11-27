# Benchmark Results: `rustban` vs `fail2ban`

Reproducible head-to-head benchmark comparing **`rustban`** (release build compiled inside Docker) against official Debian Bookworm **`fail2ban`** (`nftables` all-ports drop action + `pyinotify` backend).

> Re-run anytime with `./scripts/bench-docker.sh`. Raw machine-readable metrics are stored in [`results.json`](./results.json).

## Test Environment & Fairness Controls

| Property | Value |
|---|---|
| **Date (UTC)** | `2026-11-27T02:58:25Z` |
| **Host CPU** | `11th Gen Intel(R) Core(TM) i7-1165G7 @ 2.80GHz` (8 vCPUs, `x86_64`) |
| **Linux Kernel** | `6.17.0-40-generic` |
| **Container Runtime** | Docker `29.6.1` (`--cap-add=NET_ADMIN`, `debian:bookworm-slim`) |
| **`rustban`** | `rustban 0.1.0` (`nftables v1.0.6 (Lester Gooch #5)`) |
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
| **Disk / Binary** | Binary vs package footprint | 2.13 MiB | 22.84 MiB | **10.7x smaller** |
| **Container Image** | Minimal runtime Docker image | 84.01 MiB | 118.81 MiB | **1.4x smaller** |
| **Cold Startup** | Median boot-to-ready (5 runs) | 13.37 ms | 185.22 ms | **13.9x faster / lower** |
| **Idle Memory** | Steady RSS (`VmRSS`) | 4.17 MiB | 17.70 MiB | **4.2x less RAM** |
| **Single-IP Ban Latency** | p50 detection → kernel `nft` (20 trials) | 12.32 ms | 153.11 ms | **12.4x faster / lower** |
| **Single-IP Ban Latency** | p95 detection → kernel `nft` (20 trials) | 15.74 ms | 155.22 ms | **9.9x faster / lower** |
| **100k Noise Ingestion** | Live throughput | 2,753,078 lines/s | 53,209 lines/s | **51.7x higher** |
| **100k Noise Ingestion** | Wall time / Peak RSS | 0.036s / 4.29 MiB | 1.879s / 19.37 MiB | **51.8x faster / lower** |
| **200-Ban Attack Burst** | Wall time (200 real `nft` bans + 5k scanners + 10k noise) | 0.027s (7477.3 bans/s) | 1.024s (195.4 bans/s) | **38.3x faster / lower** |
| **200-Ban Attack Burst** | Total CPU (daemon + `nft` children) | 20 ms | 1120 ms | **56.0x faster / lower** |
| **200-Ban Attack Burst** | Peak RSS (`VmHWM`) | 6.00 MiB | 25.97 MiB | **4.3x less RAM** |
| **CLI Status (201 bans)** | Median `status` query latency (10 runs) | 3.79 ms | 44.5 ms | **11.7x faster / lower** |
| **50k Spoofed-IP Flood** | Wall time (50k unique IPs × 1 failure) | 0.168s (297,634 IPs/s) | 2.651s (18,864 IPs/s) | **15.8x faster / lower** |
| **50k Spoofed-IP Flood** | Peak RSS (`VmHWM`) | 13.00 MiB | 69.27 MiB | **5.3x less RAM** |
| **100-Ban Expiration (5s TTL)** | Userspace + child CPU during expiration | 0.0 ms | 380.0 ms | ∞ (0 ms) |
| **Offline Regex (100k lines)** | `rustban test` vs `fail2ban-regex` (10k matches) | 0.043s (2,336,449 lines/s) | 1.854s (53,932 lines/s) | **43.3x higher** |

---

## Detailed Breakdown

### 1. Startup & Idle Footprint
- **`rustban`**: `2.13 MiB` stripped static-ish Rust binary, `13.37 ms` median cold start, `4.17 MiB` RSS (`3.42 MiB` PSS), `3` OS threads.
- **`fail2ban`**: `22.84 MiB` installed package footprint (fail2ban + Python 3.11 + pyinotify), `185.22 ms` median cold start, `17.70 MiB` RSS (`15.04 MiB` PSS), `5` OS threads.

### 2. Single-IP Detection-to-Kernel-Ban Latency (20 live trials)
Time from writing 3 matching auth-failure log lines until the attacker IP is actively enforced inside the Linux kernel `nftables` set:
- **`rustban`**: min `8.03 ms`, p50 `12.32 ms`, mean `12.06 ms`, p95 `15.74 ms`, max `17.04 ms`.
- **`fail2ban`**: min `151.07 ms`, p50 `153.11 ms`, mean `165.71 ms`, p95 `155.22 ms`, max `404.11 ms`.

### 3. High-Volume Noise Log Ingestion (100,000 non-matching lines + 1 sentinel ban)
- **`rustban`**: `0.036s` (`2,753,078 lines/s`), daemon CPU `40.0 ms`, child CPU `0.0 ms`, peak RSS `4.29 MiB`.
- **`fail2ban`**: `1.879s` (`53,209 lines/s`), daemon CPU `1400.0 ms`, child CPU `0.0 ms`, peak RSS `19.37 MiB`.

### 4. Distributed Attack Burst (200 real `nftables` bans + 5,000 scanners + 10,000 noise lines)
- **`rustban`**: `0.027s` (`7477.3 bans/s`), daemon CPU `20.0 ms`, child (`nft`) CPU `0.0 ms`, total CPU `20.0 ms`, peak RSS `6.00 MiB`, steady RSS `6.00 MiB`.
- **`fail2ban`**: `1.024s` (`195.4 bans/s`), daemon CPU `640.0 ms`, child (`sh`/`nft`) CPU `480.0 ms`, total CPU `1120.0 ms`, peak RSS `25.97 MiB`, steady RSS `25.97 MiB`.
- *Note*: `rustban` drains queued events and coalesces concurrent bans into atomic batched `nft -f -` transactions, amortizing Linux kernel `nf_tables` netlink commit overhead across bursts while preserving immediate single-IP flush latency.

### 5. High-Cardinality Spoofed-IP Flood (50,000 unique IPs × 1 failure + 1 sentinel ban)
Tests memory bounding and tracking overhead under distributed botnet credential stuffing where IPs do not reach `max_retries`:
- **`rustban`**: `0.168s` (`297,634 unique IPs/s`), daemon CPU `220.0 ms`, peak RSS `13.00 MiB`.
- **`fail2ban`**: `2.651s` (`18,864 unique IPs/s`), daemon CPU `2390.0 ms`, peak RSS `69.27 MiB`.

### 6. Ban Expiration Overhead (100 active bans × 5s TTL)
Directly tests `rustban`'s core thesis — offloading ban expiration to the Linux kernel via `nftables` timeout sets:
- **`rustban`**: drained in `5.02s` with **`0.0 ms` daemon CPU** and **`0.0 ms` child (`nft`) CPU** (zero userspace wakeups, zero `nft delete element` subprocesses).
- **`fail2ban`**: drained in `5.70s` with **`110.0 ms` daemon CPU** and **`270.0 ms` child (`sh`/`nft`) CPU** (100 userspace unban timer wakeups + 100 `nft delete element` subprocesses + SQLite updates).

### 7. Offline Regex Engine (`rustban test` vs `fail2ban-regex`, 100k lines / 10k matches)
- **`rustban test`**: median `0.043s` (`2,336,449 lines/s`, runs: `[0.047, 0.0428, 0.0401]`).
- **`fail2ban-regex`**: median `1.854s` (`53,932 lines/s`, runs: `[1.7478, 1.8542, 2.1726]`).
