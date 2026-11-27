#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BENCH_DIR="${ROOT_DIR}/benchmarks"
E2E_IMAGE="rustban-e2e:test"
OUT_JSON=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --json)
      if [[ $# -lt 2 ]]; then
        echo "Missing argument for --json" >&2
        exit 1
      fi
      OUT_JSON="$2"
      shift 2
      ;;
    -h|--help)
      echo "Usage: $0 [--json <path>]"
      echo "  Runs an 8-file concurrent distributed scan stress test against rustban inside Docker"
      echo "  (161,224 concurrent lines, 80,000 unique scanner IPs, 408 live kernel nftables bans)."
      echo "  --json <path>  Optionally write raw JSON metrics to <path>."
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

TMP_OUT="$(mktemp)"
trap 'rm -f "${TMP_OUT}"' EXIT

echo "==> [1/2] Building static musl rustban E2E image inside Docker..."
docker build --target e2e --build-arg "RUSTBAN_VERSION=${RUSTBAN_VERSION:-}" -t "${E2E_IMAGE}" "${ROOT_DIR}" >/dev/null

echo "==> [2/2] Running 8-file concurrent distributed scan stress test (80k unique IPs, 408 kernel bans)..."
docker run --rm \
  --cap-add=NET_ADMIN \
  --entrypoint python3 \
  -v "${BENCH_DIR}/multi_file_stress.py:/multi_file_stress.py:ro" \
  "${E2E_IMAGE}" \
  /multi_file_stress.py > "${TMP_OUT}"

if [[ -n "${OUT_JSON}" ]]; then
  mkdir -p "$(dirname "${OUT_JSON}")"
  cp "${TMP_OUT}" "${OUT_JSON}"
fi

python3 - "${TMP_OUT}" << 'PY'
import json, sys

with open(sys.argv[1]) as f:
    r = json.load(f)

fmt_mib = lambda kib: f"{kib / 1024:.2f} MiB"

print("")
print("=== Multi-File Distributed Scan Stress Test Summary ===")
print(f"  Jails / Log files   : {r['jails']} concurrent sources ({r['idle_mem']['threads']} OS threads)")
print(f"  Total lines blasted : {r['total_lines']:,} ({r['unique_scanner_ips']:,} unique scanner IPs)")
print(f"  Kernel bans enforced: {r['actual_bans']} / {r['expected_bans']} (100%)")
print(f"  Flood wall time     : {r['wall_secs']:.3f}s ({r['lines_per_sec']:,.0f} lines/s)")
print(f"  Flood CPU           : {r['cpu']['total_cpu_ms']:.0f} ms total (daemon={r['cpu']['self_cpu_ms']:.0f} ms, nft={r['cpu']['child_cpu_ms']:.0f} ms)")
print(f"  Idle RSS (8 jails)  : {fmt_mib(r['idle_mem']['rss_kib'])}")
print(f"  Flood Peak RSS      : {fmt_mib(r['flood_mem']['hwm_kib'])}")
print(f"  Post-Prune RSS / PSS: {fmt_mib(r['post_prune_mem']['rss_kib'])} / {fmt_mib(r['post_prune_mem']['pss_kib'])}")
print(f"  Post-Prune live ban : {r['post_prune_ban_ms']:.2f} ms")
print("")

assert r["actual_bans"] >= r["expected_bans"], f"missed bans: {r['actual_bans']}/{r['expected_bans']}"
PY
