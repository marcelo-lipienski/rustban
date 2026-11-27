#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BENCH_DIR="${ROOT_DIR}/benchmarks"
OUT_DIR="${ROOT_DIR}/dist/security"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out-dir)
      OUT_DIR="$2"
      shift 2
      ;;
    -h|--help)
      echo "Usage: $0 [--out-dir <dir>]"
      echo "  Runs the live 8-vector security & exploit check suite against rustban only."
      echo "  Exits non-zero if any security vector is not PROTECTED."
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

mkdir -p "${OUT_DIR}"
OUT_JSON="${OUT_DIR}/security-report.json"
OUT_MD="${OUT_DIR}/security-report.md"

RUSTBAN_E2E_IMAGE="rustban-e2e:test"
NET_CONTAINER="sec-check-rustban-$$"

TMP_RB_IN="$(mktemp)"
TMP_RB_NET="$(mktemp)"

cleanup() {
  docker rm -f "${NET_CONTAINER}" >/dev/null 2>&1 || true
  rm -f "${TMP_RB_IN}" "${TMP_RB_NET}"
}
trap cleanup EXIT

echo "==> [1/4] Building release rustban E2E Docker image..."
docker build --target e2e --build-arg "RUSTBAN_VERSION=${RUSTBAN_VERSION:-}" -t "${RUSTBAN_E2E_IMAGE}" "${ROOT_DIR}" >/dev/null

echo "==> [2/4] Running in-container live exploit suite (7 vectors) against rustban..."
docker run --rm --cap-add=NET_ADMIN --entrypoint python3 \
  -v "${BENCH_DIR}/security_compare.py:/security_compare.py:ro" \
  "${RUSTBAN_E2E_IMAGE}" /security_compare.py rustban > "${TMP_RB_IN}"

echo "==> [3/4] Running host-to-container cross-service & established-session kill check against rustban..."
docker run -d --name "${NET_CONTAINER}" --cap-add=NET_ADMIN --entrypoint /bin/sh "${RUSTBAN_E2E_IMAGE}" -c '
cat > /tmp/rb.toml << "TOML"
[global]
table_name = "rustban"
find_time = "60s"
ban_time = "30s"
max_retries = 3
include_default_ignores = true
ignore_self = true
[jails.sshd]
enabled = true
log_path = "/tmp/net-auth.log"
fail_regex = ["Failed password for (?:invalid user )?.+ from <HOST> port \\d+ ssh2$"]
TOML
touch /tmp/net-auth.log
python3 -u -c "
import socket, threading
from datetime import datetime
def serve_ssh():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((\"0.0.0.0\", 2222)); s.listen(32)
    while True:
        c, a = s.accept()
        d = c.recv(256).decode(\"utf-8\", \"ignore\").strip()
        if d == \"BADAUTH\":
            ts = datetime.now().strftime(\"%b %e %H:%M:%S\")
            with open(\"/tmp/net-auth.log\", \"a\") as f:
                f.write(f\"{ts} host sshd[1]: Failed password for invalid user root from {a[0]} port {a[1]} ssh2\\n\"); f.flush()
            c.sendall(b\"AUTH_FAIL\\n\")
        else: c.sendall(b\"HELLO_OK\\n\")
        c.close()
def handle_http(c):
    try:
        while c.recv(256): c.sendall(b\"HTTP_OK\\n\")
    except OSError: pass
    finally: c.close()
def serve_http():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((\"0.0.0.0\", 8080)); s.listen(32)
    while True:
        c, _ = s.accept(); threading.Thread(target=handle_http, args=(c,), daemon=True).start()
def serve_udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind((\"0.0.0.0\", 5353))
    while True:
        _, a = s.recvfrom(256); s.sendto(b\"UDP_OK\\n\", a)
for fn in (serve_ssh, serve_http, serve_udp): threading.Thread(target=fn, daemon=True).start()
threading.Event().wait()
" &
exec /usr/local/bin/rustban run -c /tmp/rb.toml
' >/dev/null

CONTAINER_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${NET_CONTAINER}")"

python3 - "${NET_CONTAINER}" "${CONTAINER_IP}" "${TMP_RB_NET}" << 'PY'
import json, socket, subprocess, sys, time

cname, cip, out_file = sys.argv[1:4]

for _ in range(40):
    try:
        s = socket.create_connection((cip, 2222), timeout=0.5)
        s.sendall(b"PING\n"); assert s.recv(64).strip() == b"HELLO_OK"; s.close()
        h = socket.create_connection((cip, 8080), timeout=0.5)
        h.sendall(b"GET\n"); assert h.recv(64).strip() == b"HTTP_OK"; h.close()
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(0.5)
        u.sendto(b"PING", (cip, 5353)); assert u.recvfrom(64)[0].strip() == b"UDP_OK"; u.close()
        r = subprocess.run(["docker", "exec", cname, "nft", "list", "table", "inet", "rustban"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if r.returncode == 0:
            break
    except Exception:
        pass
    time.sleep(0.2)

est = socket.create_connection((cip, 8080), timeout=2)
est.settimeout(0.8)
est.sendall(b"GET\n")
assert est.recv(64).strip() == b"HTTP_OK"

for _ in range(3):
    s = socket.create_connection((cip, 2222), timeout=2)
    s.sendall(b"BADAUTH\n")
    assert s.recv(64).strip() == b"AUTH_FAIL"
    s.close()

banned = False
for _ in range(30):
    r = subprocess.run(["docker", "exec", cname, "nft", "list", "set", "inet", "rustban", "banned_v4"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    if r.returncode == 0 and "elements = {" in r.stdout:
        banned = True
        break
    time.sleep(0.15)

def probe_tcp(port):
    try:
        c = socket.create_connection((cip, port), timeout=0.7)
        c.close()
        return False
    except OSError:
        return True

def probe_udp(port):
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.settimeout(0.7)
    try:
        u.sendto(b"PING", (cip, port))
        u.recvfrom(64)
        return False
    except OSError:
        return True
    finally:
        u.close()

tcp_2222_dropped = probe_tcp(2222)
tcp_8080_dropped = probe_tcp(8080)
udp_5353_dropped = probe_udp(5353)

est_severed = False
try:
    est.sendall(b"GET\n")
    resp = est.recv(64)
    if not resp:
        est_severed = True
except OSError:
    est_severed = True
finally:
    est.close()

all_ok = banned and tcp_2222_dropped and tcp_8080_dropped and udp_5353_dropped and est_severed
missing = []
if not tcp_2222_dropped: missing.append("TCP 2222")
if not tcp_8080_dropped: missing.append("TCP 8080")
if not udp_5353_dropped: missing.append("UDP 5353")
if not est_severed: missing.append("established TCP 8080")

res = {
    "status": "PROTECTED" if all_ok else "VULNERABLE",
    "ban_installed": banned,
    "tcp_2222_dropped": tcp_2222_dropped,
    "tcp_8080_dropped": tcp_8080_dropped,
    "udp_5353_dropped": udp_5353_dropped,
    "established_tcp_8080_severed": est_severed,
    "detail": (
        "Dropped TCP 2222, TCP 8080, UDP 5353, AND severed already-established TCP 8080 session"
        if all_ok
        else f"BYPASS: failed to drop {', '.join(missing)}"
    ),
}
with open(out_file, "w") as f:
    json.dump(res, f, indent=2)
PY

docker rm -f "${NET_CONTAINER}" >/dev/null 2>&1 || true

echo "==> [4/4] Writing security report and verifying 8/8 vectors are PROTECTED..."
python3 - "${TMP_RB_IN}" "${TMP_RB_NET}" "${OUT_JSON}" "${OUT_MD}" << 'PY'
import json, platform, subprocess, sys
from datetime import datetime, timezone

rb_in, rb_net, out_json, out_md = sys.argv[1:5]

with open(rb_in) as f:
    rb = json.load(f)
with open(rb_net) as f:
    rb["tests"]["cross_service_and_established"] = json.load(f)

order = [
    ("self_ip_log_flood", "1. Host Self-IP Auto-Protection (Log Flood)"),
    ("cli_forced_self_lockout", "2. Manual / Forced CLI Self-Lockout Defense"),
    ("username_log_spoofing", "3. SSH Username Log-Injection IP Spoofing"),
    ("special_non_routable_ips", "4. Special / Broadcast / Non-Routable IP Protection"),
    ("shell_and_nft_injection", "5. Shell & `nftables` Syntax Injection via Logs"),
    ("ipv6_64_rotation_evasion", "6. IPv6 `/64` Host-Bit Rotation Evasion"),
    ("cross_service_and_established", "7. Cross-Service (TCP/UDP) & Established-Session Kill"),
    ("redos_and_binary_dos", "8. ReDoS & 256 KiB Binary Garbage Log DoS"),
]

passed = sum(1 for k, _ in order if rb["tests"][k]["status"] == "PROTECTED")
total = len(order)

report = {
    "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "passed": passed,
    "total": total,
    "all_protected": passed == total,
    "environment": {
        "kernel": platform.release(),
        "arch": platform.machine(),
        "docker_version": subprocess.check_output(["docker", "version", "--format", "{{.Server.Version}}"], text=True).strip(),
        "container_base": "debian:bookworm-slim",
    },
    "rustban": rb,
}

with open(out_json, "w") as f:
    json.dump(report, f, indent=2)
    f.write("\n")

rows = []
for key, title in order:
    r = rb["tests"][key]
    rows.append(f"| {title} | **{r['status']}** | {r['detail']} |")

md = f"""# Live Security Check Report (`rustban`)

Executed inside an isolated `debian:bookworm-slim` container (`--cap-add=NET_ADMIN`, Linux `{report['environment']['kernel']}`, `{report['generated_at_utc']}`).

**Result: {passed}/{total} vectors PROTECTED**

| Exploit / Attack Vector | Verdict | Observed Evidence |
|---|---|---|
{chr(10).join(rows)}
"""

with open(out_md, "w") as f:
    f.write(md)

print(md)

if passed != total:
    sys.stderr.write(f"ERROR: Security gate failed ({passed}/{total} protected).\n")
    sys.exit(1)
PY

echo "==> Security reports written to:"
echo "    - ${OUT_JSON}"
echo "    - ${OUT_MD}"
