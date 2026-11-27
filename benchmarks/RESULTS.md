# Benchmark Results: `rustban` vs `fail2ban`

Reproducible head-to-head benchmark comparing **`rustban`** (release build compiled inside Docker) against official Debian Bookworm **`fail2ban`** (`nftables` all-ports drop action + `pyinotify` backend).

> Re-run anytime with `./scripts/bench-docker.sh`. Raw machine-readable metrics are stored in [`results.json`](./results.json).

## Test Environment & Fairness Controls

| Property | Value |
|---|---|
| **Date (UTC)** | `2026-11-27T03:59:53Z` |
| **Host CPU** | `AMD EPYC 9V45 96-Core Processor` (4 vCPUs, `x86_64`) |
| **Linux Kernel** | `7.0.0-1020-azure` |
| **Container Runtime** | Docker `29.4.2` (`--cap-add=NET_ADMIN`, `debian:bookworm-slim`) |
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
| **Disk / Binary** | Binary vs package footprint | 2.19 MiB | 22.84 MiB | **10.5x smaller** |
| **Container Image** | Minimal runtime Docker image | 31.67 MiB | 43.37 MiB | **1.4x smaller** |
| **Cold Startup** | Median boot-to-ready (5 runs) | 9.49 ms | 126.68 ms | **13.3x faster / lower** |
| **Idle Memory** | Steady RSS (`VmRSS`) | 4.29 MiB | 17.67 MiB | **4.1x less RAM** |
| **Single-IP Ban Latency** | p50 detection → kernel `nft` (20 trials) | 6.48 ms | 154.2 ms | **23.8x faster / lower** |
| **Single-IP Ban Latency** | p95 detection → kernel `nft` (20 trials) | 9.94 ms | 155.41 ms | **15.6x faster / lower** |
| **100k Noise Ingestion** | Live throughput | 3,792,261 lines/s | 92,833 lines/s | **40.9x higher** |
| **100k Noise Ingestion** | Wall time / Peak RSS | 0.026s / 4.57 MiB | 1.077s / 19.45 MiB | **40.8x faster / lower** |
| **200-Ban Attack Burst** | Wall time (200 real `nft` bans + 5k scanners + 10k noise) | 0.027s (7480.5 bans/s) | 1.251s (159.9 bans/s) | **46.9x faster / lower** |
| **200-Ban Attack Burst** | Total CPU (daemon + `nft` children) | 10 ms | 1340 ms | **134.0x faster / lower** |
| **200-Ban Attack Burst** | Peak RSS (`VmHWM`) | 5.95 MiB | 26.38 MiB | **4.4x less RAM** |
| **CLI Status (201 bans)** | Median `status` query latency (10 runs) | 4.03 ms | 38.18 ms | **9.5x faster / lower** |
| **50k Spoofed-IP Flood** | Wall time (50k unique IPs × 1 failure) | 0.150s (332,336 IPs/s) | 1.511s (33,096 IPs/s) | **10.0x faster / lower** |
| **50k Spoofed-IP Flood** | Peak RSS (`VmHWM`) | 13.12 MiB | 71.35 MiB | **5.4x less RAM** |
| **100-Ban Expiration (5s TTL)** | Userspace + child CPU during expiration | 0.0 ms | 410.0 ms | ∞ (0 ms) |
| **Offline Regex (100k lines)** | `rustban test` vs `fail2ban-regex` (10k matches) | 0.030s (3,278,688 lines/s) | 1.186s (84,324 lines/s) | **38.9x higher** |

---

## Detailed Breakdown

### 1. Startup & Idle Footprint
- **`rustban`**: `2.19 MiB` stripped static-ish Rust binary, `9.49 ms` median cold start, `4.29 MiB` RSS (`3.54 MiB` PSS), `3` OS threads.
- **`fail2ban`**: `22.84 MiB` installed package footprint (fail2ban + Python 3.11 + pyinotify), `126.68 ms` median cold start, `17.67 MiB` RSS (`15.11 MiB` PSS), `5` OS threads.

### 2. Single-IP Detection-to-Kernel-Ban Latency (20 live trials)
Time from writing 3 matching auth-failure log lines until the attacker IP is actively enforced inside the Linux kernel `nftables` set:
- **`rustban`**: min `5.13 ms`, p50 `6.48 ms`, mean `7.57 ms`, p95 `9.94 ms`, max `11.8 ms`.
- **`fail2ban`**: min `152.06 ms`, p50 `154.2 ms`, mean `166.44 ms`, p95 `155.41 ms`, max `401.41 ms`.

### 3. High-Volume Noise Log Ingestion (100,000 non-matching lines + 1 sentinel ban)
- **`rustban`**: `0.026s` (`3,792,261 lines/s`), daemon CPU `30.0 ms`, child CPU `0.0 ms`, peak RSS `4.57 MiB`.
- **`fail2ban`**: `1.077s` (`92,833 lines/s`), daemon CPU `1070.0 ms`, child CPU `10.0 ms`, peak RSS `19.45 MiB`.

### 4. Distributed Attack Burst (200 real `nftables` bans + 5,000 scanners + 10,000 noise lines)
- **`rustban`**: `0.027s` (`7480.5 bans/s`), daemon CPU `10.0 ms`, child (`nft`) CPU `0.0 ms`, total CPU `10.0 ms`, peak RSS `5.95 MiB`, steady RSS `5.95 MiB`.
- **`fail2ban`**: `1.251s` (`159.9 bans/s`), daemon CPU `660.0 ms`, child (`sh`/`nft`) CPU `680.0 ms`, total CPU `1340.0 ms`, peak RSS `26.38 MiB`, steady RSS `26.38 MiB`.
- *Note*: `rustban` drains queued events and coalesces concurrent bans into atomic batched `nft -f -` transactions, amortizing Linux kernel `nf_tables` netlink commit overhead across bursts while preserving immediate single-IP flush latency.

### 5. High-Cardinality Spoofed-IP Flood (50,000 unique IPs × 1 failure + 1 sentinel ban)
Tests memory bounding and tracking overhead under distributed botnet credential stuffing where IPs do not reach `max_retries`:
- **`rustban`**: `0.150s` (`332,336 unique IPs/s`), daemon CPU `210.0 ms`, peak RSS `13.12 MiB`.
- **`fail2ban`**: `1.511s` (`33,096 unique IPs/s`), daemon CPU `1470.0 ms`, peak RSS `71.35 MiB`.

### 6. Ban Expiration Overhead (100 active bans × 5s TTL)
Directly tests `rustban`'s core thesis — offloading ban expiration to the Linux kernel via `nftables` timeout sets:
- **`rustban`**: drained in `5.03s` with **`0.0 ms` daemon CPU** and **`0.0 ms` child (`nft`) CPU** (zero userspace wakeups, zero `nft delete element` subprocesses).
- **`fail2ban`**: drained in `4.79s` with **`120.0 ms` daemon CPU** and **`290.0 ms` child (`sh`/`nft`) CPU** (100 userspace unban timer wakeups + 100 `nft delete element` subprocesses + SQLite updates).

### 7. Offline Regex Engine (`rustban test` vs `fail2ban-regex`, 100k lines / 10k matches)
- **`rustban test`**: median `0.030s` (`3,278,688 lines/s`, runs: `[0.0305, 0.0308, 0.0297]`).
- **`fail2ban-regex`**: median `1.186s` (`84,324 lines/s`, runs: `[1.174, 1.2014, 1.1859]`).
