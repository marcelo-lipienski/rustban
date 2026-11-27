#!/usr/bin/env python3
"""
Head-to-head live vulnerability / exploit test harness for rustban vs stock Debian fail2ban.
Runs inside an isolated Debian Bookworm container with CAP_NET_ADMIN and nftables.
Outputs a single JSON document to stdout with verdicts and raw observed evidence.
"""

import json
import os
import re
import signal
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime

LOG_PATH = "/tmp/sec-auth.log"
RUSTBAN_CFG = "/tmp/rustban-sec.toml"
F2B_SOCK = "/var/run/fail2ban/fail2ban.sock"
F2B_PID = "/var/run/fail2ban/fail2ban.pid"
F2B_DB = "/var/lib/fail2ban/fail2ban.sqlite3"
F2B_LOG = "/tmp/fail2ban-sec.log"


def syslog_ts() -> str:
    return datetime.now().strftime("%b %e %H:%M:%S")


def get_container_eth0_ip() -> str:
    # Determine the container's own non-loopback IPv4 address via routing table / UDP socket trick
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 80))
        ip = s.getsockname()[0]
    except OSError:
        ip = socket.gethostbyname(socket.gethostname())
    finally:
        s.close()
    return ip


def flush_nft_all():
    subprocess.run(["/usr/sbin/nft", "flush", "ruleset"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def nft_get_banned_ips(target: str) -> dict[str, list[str]]:
    if target == "rustban":
        sets = [("v4", "rustban", "banned_v4"), ("v6", "rustban", "banned_v6")]
    else:
        sets = [("v4", "f2b-table", "addr-set-sshd"), ("v6", "f2b-table", "addr6-set-sshd")]
    out = {"v4": [], "v6": []}
    for fam, tbl, st_name in sets:
        res = subprocess.run(
            ["/usr/sbin/nft", "-j", "list", "set", "inet", tbl, st_name],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        if res.returncode != 0:
            continue
        try:
            data = json.loads(res.stdout)
        except json.JSONDecodeError:
            continue
        for item in data.get("nftables", []):
            st = item.get("set")
            if not st:
                continue
            for el in st.get("elem", []):
                if isinstance(el, str):
                    out[fam].append(el)
                elif isinstance(el, dict) and "elem" in el:
                    val = el["elem"].get("val")
                    if isinstance(val, str):
                        out[fam].append(val)
                    elif isinstance(val, dict) and "prefix" in val:
                        p = val["prefix"]
                        out[fam].append(f"{p['addr']}/{p['len']}")
    return out


def nft_table_exists(target: str) -> bool:
    tbl = "rustban" if target == "rustban" else "f2b-table"
    return (
        subprocess.run(
            ["/usr/sbin/nft", "list", "table", "inet", tbl],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode
        == 0
    )


def write_rustban_config():
    # Exact production sshd regexes from rustban.toml.example + default security settings
    cfg = f"""[global]
table_name = "rustban"
find_time = "10m"
ban_time = "5m"
max_retries = 3
max_tracked_ips = 65536
max_line_bytes = 4096
include_default_ignores = true
ignore_self = true
ignore_ips = []

[jails.sshd]
enabled = true
log_path = "{LOG_PATH}"
fail_regex = [
    'Failed (?:password|publickey) for (?:invalid user )?.+ from <HOST> port \\d+ ssh2$',
    'Invalid user .+ from <HOST> port \\d+$',
    'Connection closed by (?:authenticating|invalid) user .+ <HOST> port \\d+(?: \\[preauth\\])?$',
    'Disconnected from (?:authenticating|invalid) user .+ <HOST> port \\d+(?: \\[preauth\\])?$',
    'maximum authentication attempts exceeded for (?:invalid user )?.+ from <HOST> port \\d+ ssh2 \\[preauth\\]$',
]
"""
    with open(RUSTBAN_CFG, "w") as f:
        f.write(cfg)


def write_fail2ban_config():
    for p in (F2B_SOCK, F2B_PID, F2B_DB, F2B_LOG):
        try:
            os.remove(p)
        except FileNotFoundError:
            pass
    if os.path.isdir("/etc/fail2ban/jail.d"):
        for fn in os.listdir("/etc/fail2ban/jail.d"):
            try:
                os.remove(os.path.join("/etc/fail2ban/jail.d", fn))
            except OSError:
                pass

    with open("/etc/fail2ban/fail2ban.local", "w") as f:
        f.write(
            f"[Definition]\n"
            f"loglevel = WARNING\n"
            f"logtarget = {F2B_LOG}\n"
            f"socket = {F2B_SOCK}\n"
            f"pidfile = {F2B_PID}\n"
            f"dbfile = {F2B_DB}\n"
        )

    # Stock Debian sshd filter + default ignoreip (127.0.0.1/8 ::1) + nftables allports drop
    with open("/etc/fail2ban/jail.local", "w") as f:
        f.write(
            f"[DEFAULT]\n"
            f"enabled = false\n"
            f"usedns = no\n"
            f"backend = pyinotify\n"
            f"banaction = nftables[type=allports, blocktype=drop]\n"
            f"bantime = 300\n"
            f"findtime = 600\n"
            f"maxretry = 3\n\n"
            f"[sshd]\n"
            f"enabled = true\n"
            f"filter = sshd\n"
            f"logpath = {LOG_PATH}\n"
        )


def reset_log():
    with open(LOG_PATH, "w") as f:
        f.write("")


def proc_has_open_file(pid: int, target_path: str) -> bool:
    try:
        for fd in os.listdir(f"/proc/{pid}/fd"):
            try:
                if os.readlink(f"/proc/{pid}/fd/{fd}") == target_path:
                    return True
            except OSError:
                pass
    except OSError:
        pass
    return False


class SecDaemon:
    def __init__(self, target: str):
        self.target = target
        self.proc = None
        self.pid = 0

    def start(self):
        flush_nft_all()
        reset_log()
        if self.target == "rustban":
            write_rustban_config()
            self.proc = subprocess.Popen(
                ["/usr/local/bin/rustban", "run", "-c", RUSTBAN_CFG],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self.pid = self.proc.pid
            deadline = time.perf_counter() + 10.0
            while time.perf_counter() < deadline:
                if nft_table_exists("rustban") and proc_has_open_file(self.pid, LOG_PATH):
                    return
                time.sleep(0.01)
            raise RuntimeError("rustban failed to start")
        else:
            write_fail2ban_config()
            res = subprocess.run(
                ["/usr/bin/fail2ban-client", "-x", "start"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            if res.returncode != 0:
                raise RuntimeError(f"fail2ban start failed: {res.stdout} {res.stderr}")
            deadline = time.perf_counter() + 10.0
            while time.perf_counter() < deadline:
                if os.path.exists(F2B_PID):
                    try:
                        with open(F2B_PID) as f:
                            self.pid = int(f.read().strip())
                        st = subprocess.run(
                            ["/usr/bin/fail2ban-client", "status", "sshd"],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                        )
                        if st.returncode == 0:
                            return
                    except (OSError, ValueError):
                        pass
                time.sleep(0.02)
            raise RuntimeError("fail2ban failed to start")

    def is_alive(self) -> bool:
        if self.target == "rustban":
            return self.proc is not None and self.proc.poll() is None
        return self.pid > 0 and os.path.exists(f"/proc/{self.pid}")

    def stop(self):
        if self.target == "rustban":
            if self.proc and self.proc.poll() is None:
                self.proc.send_signal(signal.SIGTERM)
                try:
                    self.proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
                    self.proc.wait()
        else:
            subprocess.run(
                ["/usr/bin/fail2ban-client", "stop"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=15,
            )
            if self.pid:
                for _ in range(40):
                    if not os.path.exists(f"/proc/{self.pid}"):
                        break
                    time.sleep(0.05)
                if os.path.exists(f"/proc/{self.pid}"):
                    try:
                        os.kill(self.pid, signal.SIGKILL)
                    except OSError:
                        pass
        flush_nft_all()


def append_lines(lines: list[str]):
    with open(LOG_PATH, "a") as f:
        for ln in lines:
            f.write(ln if ln.endswith("\n") else ln + "\n")
        f.flush()
        os.fsync(f.fileno())


def test_1_self_ip_log_flood(target: str, self_ip: str) -> dict:
    d = SecDaemon(target)
    d.start()
    try:
        ts = syslog_ts()
        append_lines(
            [f"{ts} host sshd[1001]: Failed password for invalid user root from {self_ip} port {41000+i} ssh2" for i in range(5)]
        )
        time.sleep(0.8)
        bans = nft_get_banned_ips(target)
        banned_self = self_ip in bans["v4"]
        return {
            "status": "VULNERABLE" if banned_self else "PROTECTED",
            "self_ip": self_ip,
            "banned_v4": bans["v4"],
            "detail": (
                f"Host interface IP {self_ip} WAS BANNED in nftables!"
                if banned_self
                else f"Host interface IP {self_ip} auto-protected (0 bans)"
            ),
        }
    finally:
        d.stop()


def test_2_cli_forced_self_lockout(target: str, self_ip: str) -> dict:
    d = SecDaemon(target)
    d.start()
    # Start local TCP listener bound to self_ip:2299
    stop_ev = threading.Event()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((self_ip, 2299))
    srv.listen(8)
    srv.settimeout(0.2)

    def serve():
        while not stop_ev.is_set():
            try:
                conn, _ = srv.accept()
                conn.sendall(b"OK\n")
                conn.close()
            except OSError:
                pass

    th = threading.Thread(target=serve, daemon=True)
    th.start()
    try:
        if target == "rustban":
            # First verify normal CLI refuses self-IP
            normal = subprocess.run(
                ["/usr/local/bin/rustban", "ban", self_ip, "-t", "30s"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            normal_refused = normal.returncode != 0
            # Then even with --force, test if kernel whitelist still preserves connectivity
            subprocess.run(
                ["/usr/local/bin/rustban", "ban", self_ip, "-t", "30s", "--force"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        else:
            normal_refused = False
            res = subprocess.run(
                ["/usr/bin/fail2ban-client", "set", "sshd", "banip", self_ip],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            normal_refused = res.returncode != 0

        time.sleep(0.3)
        # Attempt self-connect from self_ip -> self_ip:2299
        self_connect_ok = False
        try:
            c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            c.settimeout(1.0)
            c.bind((self_ip, 0))
            c.connect((self_ip, 2299))
            data = c.recv(16).strip()
            c.close()
            self_connect_ok = data == b"OK"
        except OSError:
            self_connect_ok = False

        return {
            "status": "PROTECTED" if self_connect_ok else "VULNERABLE",
            "normal_cli_refused": normal_refused,
            "self_traffic_survived": self_connect_ok,
            "detail": (
                f"CLI refused default ban={normal_refused}; self-traffic to {self_ip}:2299 SURVIVED even after forced ban (kernel whitelist return)"
                if self_connect_ok
                else f"SELF-LOCKOUT: manual CLI ban on {self_ip} dropped host's own traffic to {self_ip}:2299!"
            ),
        }
    finally:
        stop_ev.set()
        th.join(timeout=1.0)
        srv.close()
        d.stop()


def test_3_username_log_injection_spoofing(target: str) -> dict:
    d = SecDaemon(target)
    d.start()
    try:
        victim = "203.0.113.1"
        attacker = "198.51.100.77"
        ts = syslog_ts()
        append_lines(
            [
                f"{ts} host sshd[1002]: Failed password for invalid user root from {victim} port 22 ssh2 from {attacker} port {52000+i} ssh2"
                for i in range(5)
            ]
        )
        time.sleep(0.8)
        bans = nft_get_banned_ips(target)
        victim_banned = victim in bans["v4"]
        attacker_banned = attacker in bans["v4"]
        if victim_banned:
            status = "VULNERABLE"
            detail = f"SPOOF SUCCEEDED: victim {victim} was banned! (bans={bans['v4']})"
        elif attacker_banned:
            status = "PROTECTED"
            detail = f"Victim {victim} safe; real attacker {attacker} accurately banned"
        else:
            status = "PARTIAL"
            detail = f"Victim {victim} not banned, but attacker {attacker} also not matched (bans={bans['v4']})"
        return {
            "status": status,
            "victim_banned": victim_banned,
            "attacker_banned": attacker_banned,
            "banned_v4": bans["v4"],
            "detail": detail,
        }
    finally:
        d.stop()


def test_4_special_non_routable_ips(target: str) -> dict:
    d = SecDaemon(target)
    d.start()
    try:
        ts = syslog_ts()
        # Test special / non-routable / broadcast / multicast / loopback-adjacent / IPv4-mapped loopback
        specials = [
            "0.0.0.0",
            "127.0.0.1",
            "224.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::2",
            "::ffff:127.0.0.1",
        ]
        lines = []
        for ip in specials:
            for i in range(5):
                lines.append(
                    f"{ts} host sshd[1003]: Failed password for invalid user root from {ip} port {43000+i} ssh2"
                )
        append_lines(lines)
        time.sleep(1.0)
        bans = nft_get_banned_ips(target)
        all_banned = bans["v4"] + bans["v6"]
        return {
            "status": "VULNERABLE" if len(all_banned) > 0 else "PROTECTED",
            "tested_ips": specials,
            "banned": all_banned,
            "detail": (
                f"Banned special/non-routable address(es): {all_banned}"
                if all_banned
                else "Zero special/non-routable/broadcast/loopback-adjacent addresses banned"
            ),
        }
    finally:
        d.stop()


def test_5_shell_and_nft_injection(target: str) -> dict:
    d = SecDaemon(target)
    d.start()
    pwn_files = ["/tmp/pwned_sec1", "/tmp/pwned_sec2"]
    for p in pwn_files:
        try:
            os.remove(p)
        except FileNotFoundError:
            pass
    try:
        # Warm up table for fail2ban so we can verify table survives injection attempt
        ts = syslog_ts()
        append_lines(
            [f"{ts} host sshd[1004]: Failed password for invalid user root from 198.51.100.250 port {44000+i} ssh2" for i in range(4)]
        )
        time.sleep(0.6)

        payloads = [
            '203.0.113.9"; flush ruleset; #',
            "203.0.113.9 }; delete table inet rustban; delete table inet f2b-table; #",
            "$(touch /tmp/pwned_sec1)",
            "`touch /tmp/pwned_sec2`",
            "198.51.100.88; touch /tmp/pwned_sec1",
        ]
        lines = []
        for p in payloads:
            for i in range(5):
                lines.append(
                    f"{ts} host sshd[1005]: Failed password for invalid user root from {p} port {45000+i} ssh2"
                )
        append_lines(lines)
        time.sleep(0.8)

        pwned = [p for p in pwn_files if os.path.exists(p)]
        table_ok = nft_table_exists(target)
        bans = nft_get_banned_ips(target)
        unexpected = sorted(ip for ip in bans["v4"] + bans["v6"] if ip != "198.51.100.250")
        if pwned or not table_ok:
            status = "VULNERABLE"
            detail = f"INJECTION SUCCEEDED: rce={pwned}, table_intact={table_ok}, unexpected_bans={unexpected}"
        elif unexpected:
            status = "PARTIAL"
            detail = f"No RCE or ruleset flush, but malformed injected host strings still triggered false bans: {unexpected}"
        else:
            status = "PROTECTED"
            detail = "Blocked all shell & nftables syntax injection payloads; firewall table intact and 0 false bans"
        return {
            "status": status,
            "rce_files_created": pwned,
            "table_intact": table_ok,
            "unexpected_bans": unexpected,
            "detail": detail,
        }
    finally:
        d.stop()


def test_6_ipv6_64_rotation_evasion(target: str) -> dict:
    d = SecDaemon(target)
    d.start()
    try:
        ts = syslog_ts()
        # 5 failures from 5 distinct host addresses in the SAME attacker ISP /64 prefix
        v6_addrs = [
            "2001:db8:cafe:1234::1",
            "2001:db8:cafe:1234:1111:2222:3333:4444",
            "2001:db8:cafe:1234::dead:beef",
            "2001:db8:cafe:1234:aaaa::99",
            "2001:db8:cafe:1234::ffff:1",
        ]
        append_lines(
            [f"{ts} host sshd[1006]: Failed password for invalid user root from {ip} port {46000+i} ssh2" for i, ip in enumerate(v6_addrs)]
        )
        time.sleep(0.9)
        bans = nft_get_banned_ips(target)
        caught = any("2001:db8:cafe:1234::" in x for x in bans["v6"])
        return {
            "status": "PROTECTED" if caught else "VULNERABLE",
            "banned_v6": bans["v6"],
            "detail": (
                f"Blocked IPv6 host-bit rotation evasion -> banned {bans['v6']}"
                if caught
                else "EVADED: 0 IPv6 bans triggered across 5 failures from same /64 (tracks /128 individually)"
            ),
        }
    finally:
        d.stop()


def test_8_redos_and_binary_garbage_dos(target: str) -> dict:
    d = SecDaemon(target)
    d.start()
    try:
        ts = syslog_ts()
        # Warm up so nft table exists before timing
        append_lines(
            [f"{ts} host sshd[1007]: Failed password for invalid user root from 198.51.100.250 port {47000+i} ssh2" for i in range(4)]
        )
        time.sleep(0.6)

        # Build pathological backtracking payload + 256 KiB binary line + sentinel attacker
        redos_line = (
            f"{ts} host sshd[1008]: Failed password for invalid user "
            + ("root from 1.2.3.4 " * 120)
            + "port not_a_number\n"
        )
        sentinel = "198.51.100.99"
        sentinel_lines = "".join(
            f"{ts} host sshd[1009]: Failed password for invalid user root from {sentinel} port {48000+i} ssh2\n"
            for i in range(4)
        )

        t0 = time.perf_counter()
        with open(LOG_PATH, "ab") as f:
            for _ in range(50):
                f.write(redos_line.encode("utf-8"))
            # 256 KiB binary garbage line (invalid UTF-8 + NUL bytes)
            f.write(b"\xff\xfe\x00\x80" * 65536 + b"\n")
            f.write(sentinel_lines.encode("utf-8"))
            f.flush()
            os.fsync(f.fileno())

        banned_sentinel = False
        deadline = t0 + 15.0
        while time.perf_counter() < deadline:
            if sentinel in nft_get_banned_ips(target)["v4"]:
                banned_sentinel = True
                break
            time.sleep(0.01)
        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        alive = d.is_alive()
        ok = alive and banned_sentinel and elapsed_ms < 2000.0
        return {
            "status": "PROTECTED" if ok else "VULNERABLE",
            "daemon_alive": alive,
            "sentinel_banned": banned_sentinel,
            "recovery_ms": elapsed_ms,
            "detail": (
                f"Survived 50 ReDoS payloads + 256 KiB binary garbage and banned sentinel in {elapsed_ms} ms"
                if ok
                else f"DEGRADED/FAILED: alive={alive}, sentinel_banned={banned_sentinel}, recovery_ms={elapsed_ms}"
            ),
        }
    finally:
        d.stop()


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ("rustban", "fail2ban"):
        print("Usage: security_compare.py <rustban|fail2ban>", file=sys.stderr)
        sys.exit(2)

    target = sys.argv[1]
    self_ip = get_container_eth0_ip()
    sys.stderr.write(f"[sec:{target}] container eth0 IP={self_ip}\n")

    results = {"target": target, "self_ip": self_ip, "tests": {}}
    for key, label, fn in [
        ("self_ip_log_flood", "1/7 host self-IP auto-protection (log flood)", lambda: test_1_self_ip_log_flood(target, self_ip)),
        ("cli_forced_self_lockout", "2/7 manual/forced CLI self-lockout defense", lambda: test_2_cli_forced_self_lockout(target, self_ip)),
        ("username_log_spoofing", "3/7 SSH username log-injection IP spoofing", lambda: test_3_username_log_injection_spoofing(target)),
        ("special_non_routable_ips", "4/7 special/non-routable/broadcast IP protection", lambda: test_4_special_non_routable_ips(target)),
        ("shell_and_nft_injection", "5/7 shell & nftables syntax injection", lambda: test_5_shell_and_nft_injection(target)),
        ("ipv6_64_rotation_evasion", "6/7 IPv6 /64 host-bit rotation evasion", lambda: test_6_ipv6_64_rotation_evasion(target)),
        ("redos_and_binary_dos", "7/7 ReDoS & 256 KiB binary garbage DoS", lambda: test_8_redos_and_binary_garbage_dos(target)),
    ]:
        sys.stderr.write(f"[sec:{target}] running {label}...\n")
        results["tests"][key] = fn()

    sys.stderr.write(f"[sec:{target}] done!\n")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
