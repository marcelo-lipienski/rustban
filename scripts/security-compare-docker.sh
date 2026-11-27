#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BENCH_DIR="${ROOT_DIR}/benchmarks"
OUT_JSON="${BENCH_DIR}/security_results.json"
OUT_MD="${BENCH_DIR}/SECURITY_COMPARISON.md"

RUSTBAN_BENCH_IMAGE="rustban-e2e:test"
FAIL2BAN_BENCH_IMAGE="fail2ban-runtime:bench"

TMP_RB_IN="$(mktemp)"
TMP_F2B_IN="$(mktemp)"
TMP_RB_NET="$(mktemp)"
TMP_F2B_NET="$(mktemp)"

cleanup() {
  docker rm -f "sec-net-rustban-$$" "sec-net-fail2ban-$$" >/dev/null 2>&1 || true
  rm -f "${TMP_RB_IN}" "${TMP_F2B_IN}" "${TMP_RB_NET}" "${TMP_F2B_NET}"
}
trap cleanup EXIT

echo "==> [1/4] Ensuring Docker images are up to date (release rustban + Debian stock fail2ban)..."
docker build --target e2e -t "${RUSTBAN_BENCH_IMAGE}" "${ROOT_DIR}" >/dev/null
docker build -f "${BENCH_DIR}/Dockerfile.fail2ban" -t "${FAIL2BAN_BENCH_IMAGE}" "${BENCH_DIR}" >/dev/null

echo "==> [2/4] Running in-container live exploit suite against rustban & fail2ban..."
docker run --rm --cap-add=NET_ADMIN --entrypoint python3 \
  -v "${BENCH_DIR}/security_compare.py:/security_compare.py:ro" \
  "${RUSTBAN_BENCH_IMAGE}" /security_compare.py rustban > "${TMP_RB_IN}"

docker run --rm --cap-add=NET_ADMIN --entrypoint python3 \
  -v "${BENCH_DIR}/security_compare.py:/security_compare.py:ro" \
  "${FAIL2BAN_BENCH_IMAGE}" /security_compare.py fail2ban > "${TMP_F2B_IN}"

# Helper to run Test 8: Host-to-container live cross-service (TCP 2222, TCP 8080, UDP 5353) + established-session kill
run_cross_service_test() {
  local target="$1"
  local image="$2"
  local cname="sec-net-${target}-$$"
  local out_file="$3"

  echo "    Testing live cross-service & established-session drop against ${target}..."
  if [[ "${target}" == "rustban" ]]; then
    docker run -d --name "${cname}" --cap-add=NET_ADMIN --entrypoint /bin/sh "${image}" -c '
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
  else
    docker run -d --name "${cname}" --cap-add=NET_ADMIN --entrypoint /bin/sh "${image}" -c '
rm -f /etc/fail2ban/jail.d/* /var/run/fail2ban/fail2ban.sock /var/run/fail2ban/fail2ban.pid /var/lib/fail2ban/fail2ban.sqlite3
cat > /etc/fail2ban/jail.local << "INI"
[DEFAULT]
enabled = false
usedns = no
backend = pyinotify
banaction = nftables[type=allports, blocktype=drop]
bantime = 30
findtime = 60
maxretry = 3
[sshd]
enabled = true
filter = sshd
logpath = /tmp/net-auth.log
INI
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
fail2ban-client -x start
tail -f /dev/null
' >/dev/null
  fi

  local cip
  cip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${cname}")"

  python3 - "${target}" "${cname}" "${cip}" "${out_file}" << 'PY'
import json, socket, subprocess, sys, time

target, cname, cip, out_file = sys.argv[1:5]

# Wait for listeners + daemon readiness
for _ in range(40):
    try:
        s = socket.create_connection((cip, 2222), timeout=0.5)
        s.sendall(b"PING\n"); assert s.recv(64).strip() == b"HELLO_OK"; s.close()
        h = socket.create_connection((cip, 8080), timeout=0.5)
        h.sendall(b"GET\n"); assert h.recv(64).strip() == b"HTTP_OK"; h.close()
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(0.5)
        u.sendto(b"PING", (cip, 5353)); assert u.recvfrom(64)[0].strip() == b"UDP_OK"; u.close()
        if target == "rustban":
            r = subprocess.run(["docker", "exec", cname, "nft", "list", "table", "inet", "rustban"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if r.returncode == 0: break
        else:
            r = subprocess.run(["docker", "exec", cname, "fail2ban-client", "status", "sshd"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if r.returncode == 0: break
    except Exception:
        pass
    time.sleep(0.2)

# 1. Open ALREADY-ESTABLISHED TCP session to port 8080 before triggering ban
est = socket.create_connection((cip, 8080), timeout=2)
est.settimeout(0.8)
est.sendall(b"GET\n")
assert est.recv(64).strip() == b"HTTP_OK"

# 2. Trigger 3 bad auths on SSH mock (TCP 2222)
for _ in range(3):
    s = socket.create_connection((cip, 2222), timeout=2)
    s.sendall(b"BADAUTH\n")
    assert s.recv(64).strip() == b"AUTH_FAIL"
    s.close()

# Wait until IP appears in nftables
tbl, st_name = ("rustban", "banned_v4") if target == "rustban" else ("f2b-table", "addr-set-sshd")
banned = False
for _ in range(30):
    r = subprocess.run(["docker", "exec", cname, "nft", "list", "set", "inet", tbl, st_name], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    if r.returncode == 0 and "elements = {" in r.stdout:
        banned = True
        break
    time.sleep(0.15)

def probe_tcp(port):
    try:
        c = socket.create_connection((cip, port), timeout=0.7)
        c.close()
        return False # NOT dropped
    except OSError:
        return True # DROPPED

def probe_udp(port):
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.settimeout(0.7)
    try:
        u.sendto(b"PING", (cip, port))
        u.recvfrom(64)
        return False # NOT dropped
    except OSError:
        return True # DROPPED
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
        else f"BYPASS: failed to drop {', '.join(missing)} (TCP 2222={tcp_2222_dropped}, TCP 8080={tcp_8080_dropped}, UDP 5353={udp_5353_dropped}, est_8080={est_severed})"
    ),
}
with open(out_file, "w") as f:
    json.dump(res, f, indent=2)
PY

  docker rm -f "${cname}" >/dev/null 2>&1 || true
}

echo "==> [3/4] Running live host-to-container cross-service & established-session tests..."
run_cross_service_test rustban "${RUSTBAN_BENCH_IMAGE}" "${TMP_RB_NET}"
run_cross_service_test fail2ban "${FAIL2BAN_BENCH_IMAGE}" "${TMP_F2B_NET}"

echo "==> [4/4] Writing benchmarks/security_results.json and benchmarks/SECURITY_COMPARISON.md..."
python3 - "${TMP_RB_IN}" "${TMP_F2B_IN}" "${TMP_RB_NET}" "${TMP_F2B_NET}" "${OUT_JSON}" "${OUT_MD}" << 'PY'
import json, platform, subprocess, sys
from datetime import datetime, timezone

rb_in, f2b_in, rb_net, f2b_net, out_json, out_md = sys.argv[1:7]

with open(rb_in) as f: rb = json.load(f)
with open(f2b_in) as f: f2b = json.load(f)
with open(rb_net) as f: rb["tests"]["cross_service_and_established"] = json.load(f)
with open(f2b_net) as f: f2b["tests"]["cross_service_and_established"] = json.load(f)

combined = {
    "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "environment": {
        "kernel": platform.release(),
        "arch": platform.machine(),
        "docker_version": subprocess.check_output(["docker", "version", "--format", "{{.Server.Version}}"], text=True).strip(),
        "container_base": "debian:bookworm-slim",
    },
    "rustban": rb,
    "fail2ban": f2b,
}

with open(out_json, "w") as f:
    json.dump(combined, f, indent=2)
    f.write("\n")

def badge(status: str) -> str:
    if status == "PROTECTED": return "**PROTECTED**"
    if status == "VULNERABLE": return "**VULNERABLE**"
    return f"**{status}**"

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

rb_pass = sum(1 for k, _ in order if rb["tests"][k]["status"] == "PROTECTED")
f2b_pass = sum(1 for k, _ in order if f2b["tests"][k]["status"] == "PROTECTED")

rows = []
details = []
for key, title in order:
    r = rb["tests"][key]
    f_res = f2b["tests"][key]
    rows.append(f"| {title} | {badge(r['status'])} | {badge(f_res['status'])} |")
    details.append(
        f"### {title}\n"
        f"- **`rustban`** ({badge(r['status'])}): {r['detail']}\n"
        f"- **`fail2ban`** ({badge(f_res['status'])}): {f_res['detail']}\n"
    )

md = f"""# Live Security & Exploit Comparison: `rustban` vs `fail2ban`

Reproducible head-to-head live exploit test suite executed inside isolated `debian:bookworm-slim` containers (`--cap-add=NET_ADMIN`, `nftables 1.0.6`, Linux `{combined['environment']['kernel']}`).

> Re-run anytime with `./scripts/security-compare-docker.sh`. Raw JSON output is stored in [`security_results.json`](./security_results.json).

**Configuration under test (out-of-the-box defaults):**
- **`rustban`**: shipped `sshd` regexes from `rustban.toml.example`, default `include_default_ignores = true`, `ignore_self = true`, `prerouting @ raw` `nftables` table.
- **`fail2ban`**: official Debian Bookworm `Fail2Ban v1.0.2`, stock `/etc/fail2ban/filter.d/sshd.conf`, default `ignoreip`, `banaction = nftables[type=allports, blocktype=drop]`, `backend = pyinotify`.

## Summary Matrix (`rustban`: {rb_pass}/{len(order)} protected · `fail2ban`: {f2b_pass}/{len(order)} protected)

| Exploit / Attack Scenario | `rustban` | `fail2ban` (stock Debian) |
|---|---|---|
{chr(10).join(rows)}

---

## Observed Evidence

{chr(10).join(details)}
"""

with open(out_md, "w") as f:
    f.write(md)

print(md)
PY

echo "==> Stored security comparison results in:"
echo "    - ${OUT_JSON}"
echo "    - ${OUT_MD}"
