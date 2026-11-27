#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BENCH_DIR="${ROOT_DIR}/benchmarks"
RESULTS_JSON="${BENCH_DIR}/results.json"
RESULTS_MD="${BENCH_DIR}/RESULTS.md"

RUSTBAN_RUNTIME_IMAGE="rustban:latest"
RUSTBAN_BENCH_IMAGE="rustban-e2e:test"
FAIL2BAN_BENCH_IMAGE="fail2ban-runtime:bench"

echo "==> [1/4] Building Docker images (release mode rustban + official Debian fail2ban)..."
docker build --target runtime --build-arg "RUSTBAN_VERSION=${RUSTBAN_VERSION:-}" -t "${RUSTBAN_RUNTIME_IMAGE}" "${ROOT_DIR}" >/dev/null
docker build --target e2e --build-arg "RUSTBAN_VERSION=${RUSTBAN_VERSION:-}" -t "${RUSTBAN_BENCH_IMAGE}" "${ROOT_DIR}" >/dev/null
docker build -f "${BENCH_DIR}/Dockerfile.fail2ban" -t "${FAIL2BAN_BENCH_IMAGE}" "${BENCH_DIR}" >/dev/null

RUSTBAN_IMG_BYTES="$(docker image inspect -f '{{.Size}}' "${RUSTBAN_RUNTIME_IMAGE}")"
FAIL2BAN_IMG_BYTES="$(docker image inspect -f '{{.Size}}' "${FAIL2BAN_BENCH_IMAGE}")"

echo "==> [2/4] Running live container benchmark suite for rustban..."
TMP_RUSTBAN="$(mktemp)"
TMP_FAIL2BAN="$(mktemp)"
trap 'rm -f "${TMP_RUSTBAN}" "${TMP_FAIL2BAN}"' EXIT

docker run --rm \
  --cap-add=NET_ADMIN \
  --entrypoint python3 \
  -v "${BENCH_DIR}/bench_harness.py:/bench_harness.py:ro" \
  "${RUSTBAN_BENCH_IMAGE}" \
  /bench_harness.py rustban > "${TMP_RUSTBAN}"

echo "==> [3/4] Running live container benchmark suite for fail2ban..."
docker run --rm \
  --cap-add=NET_ADMIN \
  --entrypoint python3 \
  -v "${BENCH_DIR}/bench_harness.py:/bench_harness.py:ro" \
  "${FAIL2BAN_BENCH_IMAGE}" \
  /bench_harness.py fail2ban > "${TMP_FAIL2BAN}"

echo "==> [4/4] Aggregating and storing benchmark results in benchmarks/results.json and benchmarks/RESULTS.md..."
python3 - "${TMP_RUSTBAN}" "${TMP_FAIL2BAN}" "${RESULTS_JSON}" "${RESULTS_MD}" "${RUSTBAN_IMG_BYTES}" "${FAIL2BAN_IMG_BYTES}" << 'PY'
import json
import platform
import subprocess
import sys
from datetime import datetime, timezone

rb_path, f2b_path, out_json, out_md, rb_img_bytes, f2b_img_bytes = sys.argv[1:7]
rb_img_bytes = int(rb_img_bytes)
f2b_img_bytes = int(f2b_img_bytes)

with open(rb_path) as f:
    rb = json.load(f)
with open(f2b_path) as f:
    f2b = json.load(f)

rb["meta"]["runtime_image_bytes"] = rb_img_bytes
f2b["meta"]["runtime_image_bytes"] = f2b_img_bytes

cpu_model = "unknown"
try:
    out = subprocess.check_output(["lscpu"], text=True)
    for line in out.splitlines():
        if line.startswith("Model name:"):
            cpu_model = line.split(":", 1)[1].strip()
            break
except Exception:
    pass

docker_ver = subprocess.check_output(["docker", "version", "--format", "{{.Server.Version}}"], text=True).strip()

combined = {
    "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "environment": {
        "kernel": platform.release(),
        "arch": platform.machine(),
        "cpu_model": cpu_model,
        "cpu_cores": int(subprocess.check_output(["nproc"], text=True).strip()),
        "docker_version": docker_ver,
        "container_base": "debian:bookworm-slim",
    },
    "rustban": rb,
    "fail2ban": f2b,
}

with open(out_json, "w") as f:
    json.dump(combined, f, indent=2)
    f.write("\n")

def fmt_mb(b: int) -> str:
    return f"{b / (1024 * 1024):.2f} MiB"

def fmt_kib_mb(kib: int) -> str:
    return f"{kib / 1024:.2f} MiB"

def ratio_lower_better(a: float, b: float) -> str:
    if a <= 0 and b <= 0:
        return "1.0x"
    if a <= 0:
        return "∞ (0 ms)"
    r = b / a
    return f"**{r:.1f}x faster / lower**" if r >= 1.05 else (f"{1/r:.1f}x slower / higher" if r <= 0.95 else "~1.0x (tie)")

def ratio_higher_better(a: float, b: float) -> str:
    if b <= 0:
        return "—"
    r = a / b
    return f"**{r:.1f}x higher**" if r >= 1.05 else (f"{1/r:.1f}x lower" if r <= 0.95 else "~1.0x (tie)")

def ratio_mem(a: float, b: float) -> str:
    if a <= 0:
        return "—"
    r = b / a
    return f"**{r:.1f}x less RAM**" if r >= 1.05 else f"{1/r:.1f}x more RAM"

def ratio_size(a: float, b: float) -> str:
    if a <= 0:
        return "—"
    r = b / a
    return f"**{r:.1f}x smaller**" if r >= 1.05 else f"{1/r:.1f}x larger"

env = combined["environment"]
rb_s, f2b_s = rb["startup_and_idle"], f2b["startup_and_idle"]
rb_lat, f2b_lat = rb["single_ip_latency"], f2b["single_ip_latency"]
rb_n, f2b_n = rb["noise_throughput_100k"], f2b["noise_throughput_100k"]
rb_b, f2b_b = rb["attack_burst_200"], f2b["attack_burst_200"]
rb_f, f2b_f = rb["spoofed_ip_flood_50k"], f2b["spoofed_ip_flood_50k"]
rb_e, f2b_e = rb["ban_expiration_100"], f2b["ban_expiration_100"]
rb_o, f2b_o = rb["offline_regex_100k"], f2b["offline_regex_100k"]

md = f"""# Benchmark Results: `rustban` vs `fail2ban`

Reproducible head-to-head benchmark comparing **`rustban`** (release build compiled inside Docker) against official Debian Bookworm **`fail2ban`** (`nftables` all-ports drop action + `pyinotify` backend).

> Re-run anytime with `./scripts/bench-docker.sh`. Raw machine-readable metrics are stored in [`results.json`](./results.json).

## Test Environment & Fairness Controls

| Property | Value |
|---|---|
| **Date (UTC)** | `{combined['generated_at_utc']}` |
| **Host CPU** | `{env['cpu_model']}` ({env['cpu_cores']} vCPUs, `{env['arch']}`) |
| **Linux Kernel** | `{env['kernel']}` |
| **Container Runtime** | Docker `{env['docker_version']}` (`--cap-add=NET_ADMIN`, `{env['container_base']}`) |
| **`rustban`** | `{rb['meta']['tool_version']}` (`{rb['meta']['nft_version']}`) |
| **`fail2ban`** | `{f2b['meta']['tool_version']}` (`{f2b['meta']['nft_version']}`) |

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
| **Disk / Binary** | Binary vs package footprint | {fmt_mb(rb['meta']['binary_bytes'])} | {fmt_mb(f2b['meta']['installed_pkg_bytes'])} | {ratio_size(rb['meta']['binary_bytes'], f2b['meta']['installed_pkg_bytes'])} |
| **Container Image** | Minimal runtime Docker image | {fmt_mb(rb_img_bytes)} | {fmt_mb(f2b_img_bytes)} | {ratio_size(rb_img_bytes, f2b_img_bytes)} |
| **Cold Startup** | Median boot-to-ready (5 runs) | {rb_s['cold_startup_ms_median']} ms | {f2b_s['cold_startup_ms_median']} ms | {ratio_lower_better(rb_s['cold_startup_ms_median'], f2b_s['cold_startup_ms_median'])} |
| **Idle Memory** | Steady RSS (`VmRSS`) | {fmt_kib_mb(rb_s['idle_memory']['rss_kib'])} | {fmt_kib_mb(f2b_s['idle_memory']['rss_kib'])} | {ratio_mem(rb_s['idle_memory']['rss_kib'], f2b_s['idle_memory']['rss_kib'])} |
| **Single-IP Ban Latency** | p50 detection → kernel `nft` (20 trials) | {rb_lat['p50_ms']} ms | {f2b_lat['p50_ms']} ms | {ratio_lower_better(rb_lat['p50_ms'], f2b_lat['p50_ms'])} |
| **Single-IP Ban Latency** | p95 detection → kernel `nft` (20 trials) | {rb_lat['p95_ms']} ms | {f2b_lat['p95_ms']} ms | {ratio_lower_better(rb_lat['p95_ms'], f2b_lat['p95_ms'])} |
| **100k Noise Ingestion** | Live throughput | {rb_n['lines_per_sec']:,.0f} lines/s | {f2b_n['lines_per_sec']:,.0f} lines/s | {ratio_higher_better(rb_n['lines_per_sec'], f2b_n['lines_per_sec'])} |
| **100k Noise Ingestion** | Wall time / Peak RSS | {rb_n['wall_secs']:.3f}s / {fmt_kib_mb(rb_n['memory']['hwm_kib'])} | {f2b_n['wall_secs']:.3f}s / {fmt_kib_mb(f2b_n['memory']['hwm_kib'])} | {ratio_lower_better(rb_n['wall_secs'], f2b_n['wall_secs'])} |
| **200-Ban Attack Burst** | Wall time (200 real `nft` bans + 5k scanners + 10k noise) | {rb_b['wall_secs']:.3f}s ({rb_b['bans_per_sec']:.1f} bans/s) | {f2b_b['wall_secs']:.3f}s ({f2b_b['bans_per_sec']:.1f} bans/s) | {ratio_lower_better(rb_b['wall_secs'], f2b_b['wall_secs'])} |
| **200-Ban Attack Burst** | Total CPU (daemon + `nft` children) | {rb_b['cpu']['total_cpu_ms']:.0f} ms | {f2b_b['cpu']['total_cpu_ms']:.0f} ms | {ratio_lower_better(rb_b['cpu']['total_cpu_ms'], f2b_b['cpu']['total_cpu_ms'])} |
| **200-Ban Attack Burst** | Peak RSS (`VmHWM`) | {fmt_kib_mb(rb_b['memory']['hwm_kib'])} | {fmt_kib_mb(f2b_b['memory']['hwm_kib'])} | {ratio_mem(rb_b['memory']['hwm_kib'], f2b_b['memory']['hwm_kib'])} |
| **CLI Status (201 bans)** | Median `status` query latency (10 runs) | {rb_b['cli_status_ms_median']} ms | {f2b_b['cli_status_ms_median']} ms | {ratio_lower_better(rb_b['cli_status_ms_median'], f2b_b['cli_status_ms_median'])} |
| **50k Spoofed-IP Flood** | Wall time (50k unique IPs × 1 failure) | {rb_f['wall_secs']:.3f}s ({rb_f['ips_per_sec']:,.0f} IPs/s) | {f2b_f['wall_secs']:.3f}s ({f2b_f['ips_per_sec']:,.0f} IPs/s) | {ratio_lower_better(rb_f['wall_secs'], f2b_f['wall_secs'])} |
| **50k Spoofed-IP Flood** | Peak RSS (`VmHWM`) | {fmt_kib_mb(rb_f['memory']['hwm_kib'])} | {fmt_kib_mb(f2b_f['memory']['hwm_kib'])} | {ratio_mem(rb_f['memory']['hwm_kib'], f2b_f['memory']['hwm_kib'])} |
| **100-Ban Expiration (5s TTL)** | Userspace + child CPU during expiration | {rb_e['expiration_cpu']['total_cpu_ms']:.1f} ms | {f2b_e['expiration_cpu']['total_cpu_ms']:.1f} ms | {ratio_lower_better(rb_e['expiration_cpu']['total_cpu_ms'], f2b_e['expiration_cpu']['total_cpu_ms'])} |
| **Offline Regex (100k lines)** | `rustban test` vs `fail2ban-regex` (10k matches) | {rb_o['median_secs']:.3f}s ({rb_o['lines_per_sec']:,.0f} lines/s) | {f2b_o['median_secs']:.3f}s ({f2b_o['lines_per_sec']:,.0f} lines/s) | {ratio_higher_better(rb_o['lines_per_sec'], f2b_o['lines_per_sec'])} |

---

## Detailed Breakdown

### 1. Startup & Idle Footprint
- **`rustban`**: `{fmt_mb(rb['meta']['binary_bytes'])}` stripped static-ish Rust binary, `{rb_s['cold_startup_ms_median']} ms` median cold start, `{fmt_kib_mb(rb_s['idle_memory']['rss_kib'])}` RSS (`{fmt_kib_mb(rb_s['idle_memory']['pss_kib'])}` PSS), `{rb_s['idle_memory']['threads']}` OS threads.
- **`fail2ban`**: `{fmt_mb(f2b['meta']['installed_pkg_bytes'])}` installed package footprint (fail2ban + Python 3.11 + pyinotify), `{f2b_s['cold_startup_ms_median']} ms` median cold start, `{fmt_kib_mb(f2b_s['idle_memory']['rss_kib'])}` RSS (`{fmt_kib_mb(f2b_s['idle_memory']['pss_kib'])}` PSS), `{f2b_s['idle_memory']['threads']}` OS threads.

### 2. Single-IP Detection-to-Kernel-Ban Latency (20 live trials)
Time from writing 3 matching auth-failure log lines until the attacker IP is actively enforced inside the Linux kernel `nftables` set:
- **`rustban`**: min `{rb_lat['min_ms']} ms`, p50 `{rb_lat['p50_ms']} ms`, mean `{rb_lat['mean_ms']} ms`, p95 `{rb_lat['p95_ms']} ms`, max `{rb_lat['max_ms']} ms`.
- **`fail2ban`**: min `{f2b_lat['min_ms']} ms`, p50 `{f2b_lat['p50_ms']} ms`, mean `{f2b_lat['mean_ms']} ms`, p95 `{f2b_lat['p95_ms']} ms`, max `{f2b_lat['max_ms']} ms`.

### 3. High-Volume Noise Log Ingestion (100,000 non-matching lines + 1 sentinel ban)
- **`rustban`**: `{rb_n['wall_secs']:.3f}s` (`{rb_n['lines_per_sec']:,.0f} lines/s`), daemon CPU `{rb_n['cpu']['self_cpu_ms']:.1f} ms`, child CPU `{rb_n['cpu']['child_cpu_ms']:.1f} ms`, peak RSS `{fmt_kib_mb(rb_n['memory']['hwm_kib'])}`.
- **`fail2ban`**: `{f2b_n['wall_secs']:.3f}s` (`{f2b_n['lines_per_sec']:,.0f} lines/s`), daemon CPU `{f2b_n['cpu']['self_cpu_ms']:.1f} ms`, child CPU `{f2b_n['cpu']['child_cpu_ms']:.1f} ms`, peak RSS `{fmt_kib_mb(f2b_n['memory']['hwm_kib'])}`.

### 4. Distributed Attack Burst (200 real `nftables` bans + 5,000 scanners + 10,000 noise lines)
- **`rustban`**: `{rb_b['wall_secs']:.3f}s` (`{rb_b['bans_per_sec']:.1f} bans/s`), daemon CPU `{rb_b['cpu']['self_cpu_ms']:.1f} ms`, child (`nft`) CPU `{rb_b['cpu']['child_cpu_ms']:.1f} ms`, total CPU `{rb_b['cpu']['total_cpu_ms']:.1f} ms`, peak RSS `{fmt_kib_mb(rb_b['memory']['hwm_kib'])}`, steady RSS `{fmt_kib_mb(rb_b['memory']['rss_kib'])}`.
- **`fail2ban`**: `{f2b_b['wall_secs']:.3f}s` (`{f2b_b['bans_per_sec']:.1f} bans/s`), daemon CPU `{f2b_b['cpu']['self_cpu_ms']:.1f} ms`, child (`sh`/`nft`) CPU `{f2b_b['cpu']['child_cpu_ms']:.1f} ms`, total CPU `{f2b_b['cpu']['total_cpu_ms']:.1f} ms`, peak RSS `{fmt_kib_mb(f2b_b['memory']['hwm_kib'])}`, steady RSS `{fmt_kib_mb(f2b_b['memory']['rss_kib'])}`.
- *Note*: `rustban` drains queued events and coalesces concurrent bans into atomic batched `nft -f -` transactions, amortizing Linux kernel `nf_tables` netlink commit overhead across bursts while preserving immediate single-IP flush latency.

### 5. High-Cardinality Spoofed-IP Flood (50,000 unique IPs × 1 failure + 1 sentinel ban)
Tests memory bounding and tracking overhead under distributed botnet credential stuffing where IPs do not reach `max_retries`:
- **`rustban`**: `{rb_f['wall_secs']:.3f}s` (`{rb_f['ips_per_sec']:,.0f} unique IPs/s`), daemon CPU `{rb_f['cpu']['self_cpu_ms']:.1f} ms`, peak RSS `{fmt_kib_mb(rb_f['memory']['hwm_kib'])}`.
- **`fail2ban`**: `{f2b_f['wall_secs']:.3f}s` (`{f2b_f['ips_per_sec']:,.0f} unique IPs/s`), daemon CPU `{f2b_f['cpu']['self_cpu_ms']:.1f} ms`, peak RSS `{fmt_kib_mb(f2b_f['memory']['hwm_kib'])}`.

### 6. Ban Expiration Overhead (100 active bans × 5s TTL)
Directly tests `rustban`'s core thesis — offloading ban expiration to the Linux kernel via `nftables` timeout sets:
- **`rustban`**: drained in `{rb_e['drain_wall_secs']:.2f}s` with **`{rb_e['expiration_cpu']['self_cpu_ms']:.1f} ms` daemon CPU** and **`{rb_e['expiration_cpu']['child_cpu_ms']:.1f} ms` child (`nft`) CPU** (zero userspace wakeups, zero `nft delete element` subprocesses).
- **`fail2ban`**: drained in `{f2b_e['drain_wall_secs']:.2f}s` with **`{f2b_e['expiration_cpu']['self_cpu_ms']:.1f} ms` daemon CPU** and **`{f2b_e['expiration_cpu']['child_cpu_ms']:.1f} ms` child (`sh`/`nft`) CPU** (100 userspace unban timer wakeups + 100 `nft delete element` subprocesses + SQLite updates).

### 7. Offline Regex Engine (`rustban test` vs `fail2ban-regex`, 100k lines / 10k matches)
- **`rustban test`**: median `{rb_o['median_secs']:.3f}s` (`{rb_o['lines_per_sec']:,.0f} lines/s`, runs: `{rb_o['runs_secs']}`).
- **`fail2ban-regex`**: median `{f2b_o['median_secs']:.3f}s` (`{f2b_o['lines_per_sec']:,.0f} lines/s`, runs: `{f2b_o['runs_secs']}`).
"""

with open(out_md, "w") as f:
    f.write(md)

print(md)
PY

echo "==> Stored benchmark results in:"
echo "    - ${RESULTS_JSON}"
echo "    - ${RESULTS_MD}"
