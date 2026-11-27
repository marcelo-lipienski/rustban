#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTAINER_NAME="rustban-e2e-$$"
E2E_IMAGE="rustban-e2e:test"
TESTER_IMAGE="rustban-tester:test"
RUNTIME_IMAGE="${RUSTBAN_IMAGE:-rustban:latest}"

cleanup() {
  docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" >&2
  echo "--- container logs ---" >&2
  docker logs "${CONTAINER_NAME}" 2>&1 || true
  exit 1
}

echo "==> [1/8] Compiling release mode and running Cargo release + security exploit tests inside Docker..."
docker build --target tester -t "${TESTER_IMAGE}" "${ROOT_DIR}"
docker build --target runtime -t "${RUNTIME_IMAGE}" "${ROOT_DIR}"
docker build --target e2e -t "${E2E_IMAGE}" "${ROOT_DIR}"

echo "==> [2/8] Starting isolated rustban container (CAP_NET_ADMIN) with live TCP responder..."
docker run -d \
  --name "${CONTAINER_NAME}" \
  --cap-add=NET_ADMIN \
  --entrypoint /bin/sh \
  "${E2E_IMAGE}" \
  -c '
cat > /tmp/rustban-e2e.toml << "TOML"
[global]
table_name = "rustban"
find_time = "30s"
ban_time = "5s"
max_retries = 3
include_default_ignores = true
ignore_self = true
ignore_ips = []

[jails.test-sshd]
enabled = true
log_path = "/tmp/test-auth.log"
fail_regex = [
  "Failed password for (?:invalid user )?.+ from <HOST> port \\d+ ssh2$"
]
TOML

touch /tmp/test-auth.log

python3 -u -c "
import socket, threading

def serve_ssh():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((\"0.0.0.0\", 2222))
    s.listen(64)
    while True:
        conn, addr = s.accept()
        ip, port = addr[0], addr[1]
        data = conn.recv(512).decode(\"utf-8\", \"ignore\").strip()
        if data == \"BADAUTH\":
            with open(\"/tmp/test-auth.log\", \"a\") as f:
                f.write(f\"Failed password for invalid user root from {ip} port {port} ssh2\\n\")
                f.flush()
            conn.sendall(b\"AUTH_FAIL\\n\")
        elif data.startswith(\"BADUSER:\"):
            user = data[len(\"BADUSER:\"):]
            with open(\"/tmp/test-auth.log\", \"a\") as f:
                f.write(f\"Failed password for invalid user {user} from {ip} port {port} ssh2\\n\")
                f.flush()
            conn.sendall(b\"AUTH_FAIL\\n\")
        else:
            conn.sendall(b\"HELLO_OK\\n\")
        conn.close()

def handle_http_client(conn):
    try:
        while True:
            data = conn.recv(256)
            if not data:
                break
            conn.sendall(b\"HTTP_OK\\n\")
    except OSError:
        pass
    finally:
        conn.close()

def serve_http():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((\"0.0.0.0\", 8080))
    s.listen(64)
    while True:
        conn, _ = s.accept()
        threading.Thread(target=handle_http_client, args=(conn,), daemon=True).start()

def serve_udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((\"0.0.0.0\", 5353))
    while True:
        _, addr = s.recvfrom(512)
        s.sendto(b\"UDP_OK\\n\", addr)

for fn in (serve_ssh, serve_http, serve_udp):
    threading.Thread(target=fn, daemon=True).start()
threading.Event().wait()
" &

exec /usr/local/bin/rustban run -c /tmp/rustban-e2e.toml
' >/dev/null

CONTAINER_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${CONTAINER_NAME}")"
if [[ -z "${CONTAINER_IP}" ]]; then
  fail "Could not determine container IP address"
fi
echo "    Container IP: ${CONTAINER_IP}"

# Wait for rustban nftables table and all 3 service listeners (TCP 2222, TCP 8080, UDP 5353)
for _ in $(seq 1 30); do
  if docker exec "${CONTAINER_NAME}" rustban status --json | grep -q '"exists": true'; then
    if python3 -c "
import socket
s = socket.create_connection(('${CONTAINER_IP}', 2222), timeout=1)
s.sendall(b'PING\n'); assert s.recv(64).strip() == b'HELLO_OK'; s.close()
h = socket.create_connection(('${CONTAINER_IP}', 8080), timeout=1)
h.sendall(b'GET\n'); assert h.recv(64).strip() == b'HTTP_OK'; h.close()
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(1)
u.sendto(b'PING', ('${CONTAINER_IP}', 5353)); assert u.recvfrom(64)[0].strip() == b'UDP_OK'; u.close()
" 2>/dev/null; then
      break
    fi
  fi
  sleep 0.2
done

echo "==> [3/8] Verifying pre-ban connectivity on all services (TCP 2222, TCP 8080, UDP 5353)..."
python3 -c "
import socket
s = socket.create_connection(('${CONTAINER_IP}', 2222), timeout=2)
s.sendall(b'PING\n'); assert s.recv(64).strip() == b'HELLO_OK'; s.close()
h = socket.create_connection(('${CONTAINER_IP}', 8080), timeout=2)
h.sendall(b'GET\n'); assert h.recv(64).strip() == b'HTTP_OK'; h.close()
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(2)
u.sendto(b'PING', ('${CONTAINER_IP}', 5353)); assert u.recvfrom(64)[0].strip() == b'UDP_OK'; u.close()
print('    All 3 services reachable pre-ban: TCP 2222, TCP 8080, UDP 5353')
" || fail "Pre-ban multi-service connectivity failed"

echo "==> [4/8 & 5/8] Triggering ban via test-sshd (TCP 2222) and proving ALL ports/protocols & established sessions are dropped..."
python3 -c "
import json, socket, subprocess, time

container_ip = '${CONTAINER_IP}'
container_name = '${CONTAINER_NAME}'

# 1. Open an ALREADY-ESTABLISHED TCP session to unrelated service on port 8080 before the ban
est = socket.create_connection((container_ip, 8080), timeout=2)
est.settimeout(0.7)
est.sendall(b'GET\n')
assert est.recv(64).strip() == b'HTTP_OK', 'established session failed pre-ban'

# 2. Trigger 3 failed auth attempts on test-sshd (TCP 2222)
for i in range(3):
    s = socket.create_connection((container_ip, 2222), timeout=2)
    s.sendall(b'BADAUTH\n')
    assert s.recv(64).strip() == b'AUTH_FAIL', f'attempt {i+1} did not reach sshd mock'
    s.close()

# 3. Wait for rustban to install the kernel nftables ban
status = None
for _ in range(25):
    raw = subprocess.check_output(['docker', 'exec', container_name, 'rustban', 'status', '--json'])
    d = json.loads(raw)
    if len(d.get('bans', [])) >= 1:
        status = d
        break
    time.sleep(0.2)
assert status is not None, 'expected host IP to be banned in nftables'
b = status['bans'][0]
assert b['comment'] == 'test-sshd', f'unexpected comment: {b}'
assert (b['expires_secs'] or 0) > 0, f'expected positive expires_secs: {b}'
ip, jail, exp = b['ip'], b['comment'], b['expires_secs']
print(f'    Kernel nftables ban active: ip={ip} jail={jail} expires={exp}s')

# 4. Prove NEW connections to TCP 2222 (triggering service) and TCP 8080 (unrelated service) are DROPPED
for port, label in ((2222, 'TCP 2222 (test-sshd)'), (8080, 'TCP 8080 (unrelated HTTP)')):
    blocked = False
    try:
        s = socket.create_connection((container_ip, port), timeout=0.7)
        s.close()
    except (TimeoutError, socket.timeout, OSError):
        blocked = True
    assert blocked, f'Connection to {label} succeeded while IP was banned!'

# 5. Prove UDP 5353 (unrelated UDP service) is DROPPED
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
u.settimeout(0.7)
u.sendto(b'PING', (container_ip, 5353))
udp_blocked = False
try:
    u.recvfrom(64)
except (TimeoutError, socket.timeout, OSError):
    udp_blocked = True
finally:
    u.close()
assert udp_blocked, 'UDP 5353 packet succeeded while IP was banned!'

# 6. Prove the ALREADY-ESTABLISHED TCP session on port 8080 is immediately severed (prerouting @ raw)
est_severed = False
try:
    est.sendall(b'GET\n')
    resp = est.recv(64)
    if not resp:
        est_severed = True
except (TimeoutError, socket.timeout, OSError):
    est_severed = True
finally:
    est.close()
assert est_severed, 'Already-established TCP 8080 session stayed alive while IP was banned!'
print('    Verified kernel dropped TCP 2222, TCP 8080, UDP 5353, AND severed established TCP 8080 session')
" || fail "Multi-service/port or established-session drop check failed"

docker exec "${CONTAINER_NAME}" rustban status --json | python3 -c '
import json, sys
d = json.load(sys.stdin)
bans = d.get("bans", [])
assert len(bans) == 1, f"expected ban still active when checking counter: {bans}"
b = bans[0]
assert b["packets"] > 0 and b["bytes"] > 0, f"expected dropped packet counter > 0, got: {b}"
pkts, nbytes = b["packets"], b["bytes"]
print(f"    Kernel drop counter verified: packets={pkts} bytes={nbytes}")
' || fail "Kernel packet drop counter did not increment"

echo "==> [6/8] Waiting for kernel nftables timeout (5s) to expire automatically..."
EXPIRED=0
for _ in $(seq 1 40); do
  if docker exec "${CONTAINER_NAME}" rustban status --json | python3 -c '
import json, sys
d = json.load(sys.stdin)
sys.exit(0 if len(d.get("bans", [])) == 0 else 1)
'; then
    EXPIRED=1
    break
  fi
  sleep 0.25
done
if [[ "${EXPIRED}" -ne 1 ]]; then
  fail "Kernel nftables ban did not expire within expected window"
fi

python3 -c "
import socket
s = socket.create_connection(('${CONTAINER_IP}', 2222), timeout=2)
s.sendall(b'PING\n'); assert s.recv(64).strip() == b'HELLO_OK'; s.close()
h = socket.create_connection(('${CONTAINER_IP}', 8080), timeout=2)
h.sendall(b'GET\n'); assert h.recv(64).strip() == b'HTTP_OK'; h.close()
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(2)
u.sendto(b'PING', ('${CONTAINER_IP}', 5353)); assert u.recvfrom(64)[0].strip() == b'UDP_OK'; u.close()
" || fail "All services did not recover after kernel timeout expiration"
echo "    Auto-unban verified: TCP 2222, TCP 8080, and UDP 5353 all recovered after kernel TTL expiry!"

echo "==> [7/8] Running LIVE exploit attempts against the container (host-IP self-ban, log spoofing, injection, IPv6 rotation)..."

# 7a. Verify container's own IP is automatically in kernel whitelist_v4 (ignore_self = true)
docker exec "${CONTAINER_NAME}" rustban status --json | python3 -c "
import json, sys
d = json.load(sys.stdin)
wl = d.get('whitelist_v4', [])
assert '${CONTAINER_IP}' in wl or '${CONTAINER_IP}/32' in wl, f'host self IP ${CONTAINER_IP} missing from whitelist_v4: {wl}'
print('    Verified ignore_self populated kernel whitelist_v4 with container IP (${CONTAINER_IP})')
" || fail "ignore_self did not protect container IP in whitelist_v4"

# 7b. Exploit attempt: username log-injection trying to frame container's own IP AND a victim IP (203.0.113.1)
for i in 1 2 3; do
  python3 -c "
import socket
s = socket.create_connection(('${CONTAINER_IP}', 2222), timeout=2)
s.sendall(b'BADUSER:root from 203.0.113.1 port 22 ssh2\n')
resp = s.recv(64).strip()
s.close()
assert resp == b'AUTH_FAIL'
" || fail "Spoofed username probe #${i} failed"
done

sleep 0.6
docker exec "${CONTAINER_NAME}" rustban status --json | python3 -c "
import json, sys
d = json.load(sys.stdin)
ips = [b['ip'] for b in d.get('bans', [])]
assert '203.0.113.1' not in ips, f'EXPLOIT SUCCEEDED: spoofed victim IP 203.0.113.1 was banned! bans={ips}'
assert '${CONTAINER_IP}' not in ips, f'EXPLOIT SUCCEEDED: container self IP was banned! bans={ips}'
assert len(ips) == 1, f'expected attacker bridge IP to be banned instead of victim, got: {ips}'
print(f'    Blocked log-injection IP spoofing: victim 203.0.113.1 safe, real attacker {ips[0]} banned')
" || fail "Username log-injection exploit check failed"

# Clear attacker ban so subsequent host checks run cleanly
docker exec "${CONTAINER_NAME}" rustban flush >/dev/null

# 7c. Exploit attempt: direct log flood attempting to ban the container's own IP, 0.0.0.0, ::1, ::2, 255.255.255.255, and nft syntax injection
docker exec "${CONTAINER_NAME}" /bin/sh -c "
for ip in '${CONTAINER_IP}' '0.0.0.0' '127.0.0.1' '224.0.0.1' '255.255.255.255' '::' '::1' '::2' '::ffff:127.0.0.1' '203.0.113.5\"; flush ruleset; #'; do
  for n in 1 2 3 4; do
    echo \"Failed password for invalid user root from \${ip} port 2222 ssh2\" >> /tmp/test-auth.log
  done
done
"
sleep 0.6
docker exec "${CONTAINER_NAME}" rustban status --json | python3 -c '
import json, sys
d = json.load(sys.stdin)
bans = d.get("bans", [])
assert d["exists"] is True, "table inet rustban disappeared after nft injection attempt!"
assert len(bans) == 0, f"EXPLOIT SUCCEEDED: forbidden/self IP was banned! bans={bans}"
print("    Blocked self-IP, special-range, ::/64 bypass, and nft-syntax log injection attempts")
' || fail "Direct self-IP / special-range / injection exploit check failed"

# 7d. Exploit attempt: CLI ban of container self-IP, ::1, ::2, and --reason/--table injection
for bad_cmd in \
  "rustban ban ${CONTAINER_IP} -t 30s" \
  "rustban ban ::1 -t 30s --force" \
  "rustban ban ::2 -t 30s --force" \
  "rustban ban 0.0.0.0 -t 30s --force" \
  "rustban ban 203.0.113.9 -t 30s -r 'x\"}; flush ruleset; #'" \
  "rustban status --table 'rustban; flush ruleset'"
do
  if docker exec "${CONTAINER_NAME}" /bin/sh -c "${bad_cmd}" >/dev/null 2>&1; then
    fail "EXPLOIT SUCCEEDED: dangerous CLI command was accepted: ${bad_cmd}"
  fi
done

# 7e. Defense-in-depth proof: even if admin runs `--force` on container's own IP, kernel whitelist_v4 `return` STILL prevents self-lockout!
docker exec "${CONTAINER_NAME}" rustban ban "${CONTAINER_IP}" -t 30s --force >/dev/null
docker exec "${CONTAINER_NAME}" python3 -c "
import socket
s = socket.create_connection(('${CONTAINER_IP}', 2222), timeout=2)
s.sendall(b'PING\n')
assert s.recv(64).strip() == b'HELLO_OK'
s.close()
" || fail "Kernel whitelist_v4 failed to prevent self-lockout under --force!"
docker exec "${CONTAINER_NAME}" rustban flush >/dev/null
echo "    Verified kernel whitelist_v4 prevents self-lockout even under --force"

# 7f. Exploit attempt: IPv6 host-bit rotation evasion across 3 distinct hosts in same /64
docker exec "${CONTAINER_NAME}" /bin/sh -c '
echo "Failed password for root from 2001:db8:cafe:1234::1 port 40001 ssh2" >> /tmp/test-auth.log
echo "Failed password for root from 2001:db8:cafe:1234:1111:2222:3333:4444 port 40002 ssh2" >> /tmp/test-auth.log
echo "Failed password for root from 2001:db8:cafe:1234::dead:beef port 40003 ssh2" >> /tmp/test-auth.log
'
sleep 0.6
docker exec "${CONTAINER_NAME}" rustban status --json | python3 -c '
import json, sys
d = json.load(sys.stdin)
ips = [b["ip"] for b in d.get("bans", [])]
assert "2001:db8:cafe:1234::/64" in ips, f"IPv6 /64 rotation evaded ban! bans={ips}"
print("    Blocked IPv6 host-bit rotation evasion -> banned 2001:db8:cafe:1234::/64")
' || fail "IPv6 rotation evasion check failed"
docker exec "${CONTAINER_NAME}" rustban flush >/dev/null

echo "==> [8/8] Verifying CLI ban/unban/flush/test/teardown..."
docker exec "${CONTAINER_NAME}" rustban ban 2001:db8:abcd:1234:dead:beef::9 -t 30s -r manual >/dev/null
docker exec "${CONTAINER_NAME}" rustban unban 2001:db8:abcd:1234::/64 >/dev/null
docker exec "${CONTAINER_NAME}" rustban status --json | python3 -c '
import json, sys
d = json.load(sys.stdin)
assert len(d["bans"]) == 0, f"expected empty bans after unban, got: {d}"
' || fail "Manual unban failed"

TEST_OUT="$(docker exec "${CONTAINER_NAME}" rustban test -c /tmp/rustban-e2e.toml /tmp/test-auth.log)"
echo "${TEST_OUT}" | grep -q "matches=" || fail "rustban test output unexpected: ${TEST_OUT}"

CHECK_OUT="$(docker exec "${CONTAINER_NAME}" rustban check -c /tmp/rustban-e2e.toml --strict)"
echo "${CHECK_OUT}" | grep -q "Config OK:" || fail "rustban check output unexpected: ${CHECK_OUT}"

# Verify SIGHUP live reload preserves active kernel bans, updates whitelist & ignore_interfaces, and rejects broken config safely
docker exec "${CONTAINER_NAME}" rustban ban 198.51.100.42 -t 60s -r pre-reload >/dev/null
docker exec "${CONTAINER_NAME}" /bin/sh -c 'cat > /tmp/rustban-e2e.toml << "TOML"
[global]
table_name = "rustban"
find_time = "30s"
ban_time = "5s"
max_retries = 3
include_default_ignores = true
ignore_self = true
ignore_self_refresh = "30s"
ignore_ips = ["198.51.100.200/32"]
ignore_interfaces = ["lo"]

[jails.test-sshd]
enabled = true
log_path = "/tmp/test-auth.log"
fail_regex = [
  "Failed password for (?:invalid user )?.+ from <HOST> port \\d+ ssh2$"
]
TOML'
docker exec "${CONTAINER_NAME}" /bin/sh -c 'kill -HUP 1'
sleep 0.5
docker exec "${CONTAINER_NAME}" rustban status --json | python3 -c '
import json, sys
d = json.load(sys.stdin)
ips = [b["ip"] for b in d.get("bans", [])]
wl = d.get("whitelist_v4", [])
assert "198.51.100.42" in ips, f"SIGHUP lost active kernel ban! bans={ips}"
assert "198.51.100.200" in wl or "198.51.100.200/32" in wl, f"SIGHUP did not apply updated whitelist_v4: {wl}"
print("    Verified SIGHUP reload updated whitelist_v4 and preserved active kernel ban")
' || fail "SIGHUP reload verification failed"
docker exec "${CONTAINER_NAME}" nft list chain inet rustban prerouting | grep -q 'iifname' || fail "SIGHUP did not install iifname rule"

# Verify invalid config on SIGHUP is rejected without killing the daemon
docker exec "${CONTAINER_NAME}" /bin/sh -c 'echo "not = [valid toml" > /tmp/rustban-e2e.toml && kill -HUP 1'
sleep 0.4
docker exec "${CONTAINER_NAME}" /bin/sh -c 'kill -0 1' || fail "Daemon exited after invalid SIGHUP config!"
docker exec "${CONTAINER_NAME}" rustban status --json | python3 -c '
import json, sys
d = json.load(sys.stdin)
assert any(b["ip"] == "198.51.100.42" for b in d.get("bans", [])), f"Daemon lost state after bad SIGHUP: {d}"
print("    Verified invalid SIGHUP config rejected while keeping daemon & bans alive")
' || fail "Invalid SIGHUP config check failed"

docker exec "${CONTAINER_NAME}" rustban teardown >/dev/null
docker exec "${CONTAINER_NAME}" rustban status --json | python3 -c '
import json, sys
d = json.load(sys.stdin)
assert d["exists"] is False, f"expected table removed after teardown, got: {d}"
' || fail "Teardown failed"

echo ""
echo "ALL TESTS & EXPLOIT CHECKS PASSED! rustban built in Docker (--release), passed all Cargo + exploit tests, and resisted all live container exploit attempts."
