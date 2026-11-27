#!/usr/bin/env python3
"""
Reproducible apples-to-apples benchmark harness for rustban vs fail2ban.
Runs inside an isolated Debian Bookworm container with CAP_NET_ADMIN and nftables.
Outputs a single JSON document to stdout with all raw measurements.
"""

import json
import os
import re
import shutil
import signal
import statistics
import subprocess
import sys
import time
from datetime import datetime

CLK_TCK = os.sysconf(os.sysconf_names["SC_CLK_TCK"])

# Same exact single-line SSH failure regex for both rustban and fail2ban.
RUSTBAN_REGEX = r"Failed password for (?:invalid user )?.+ from <HOST> port \d+ ssh2$"
FAIL2BAN_REGEX = r"^.*sshd\[\d+\]: Failed password for (?:invalid user )?.+ from <HOST> port \d+ ssh2$"

LOG_PATH = "/tmp/bench-auth.log"
RUSTBAN_CFG = "/tmp/rustban-bench.toml"
F2B_SOCK = "/var/run/fail2ban/fail2ban.sock"
F2B_PID = "/var/run/fail2ban/fail2ban.pid"
F2B_DB = "/var/lib/fail2ban/fail2ban.sqlite3"
F2B_LOG = "/tmp/fail2ban-bench.log"

NOISE_TEMPLATES = [
    "{ts} bench sshd[1001]: Accepted publickey for deploy from 198.51.100.254 port 51234 ssh2: ED25519 SHA256:abcdef1234567890",
    "{ts} bench sshd[1002]: pam_unix(sshd:session): session opened for user deploy(uid=1000) by (uid=0)",
    "{ts} bench sshd[1002]: pam_unix(sshd:session): session closed for user deploy",
    "{ts} bench CRON[2041]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)",
    "{ts} bench systemd[1]: Started Session 421 of User deploy.",
    "{ts} bench kernel: [12345.678901] eth0: Link is Up - 1Gbps/Full - flow control rx/tx",
    "{ts} bench nginx[3010]: 198.51.100.254 - - [26/Nov/2026:23:45:00 +0000] \"GET /healthz HTTP/1.1\" 200 2 \"-\" \"kube-probe/1.30\"",
    "{ts} bench sshd[1099]: Received disconnect from 198.51.100.254 port 55102:11: disconnected by user",
]


def syslog_ts() -> str:
    return datetime.now().strftime("%b %e %H:%M:%S")


def fail_line(ip: str, port: int = 40000, ts: str | None = None) -> str:
    t = ts or syslog_ts()
    return f"{t} bench sshd[4242]: Failed password for invalid user root from {ip} port {port} ssh2\n"


def run_cmd(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=check)


def flush_nft_all():
    subprocess.run(["/usr/sbin/nft", "flush", "ruleset"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def read_proc_mem(pid: int) -> dict:
    rss_kib = 0
    hwm_kib = 0
    threads = 0
    pss_kib = 0
    try:
        with open(f"/proc/{pid}/status", "r") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    rss_kib = int(line.split()[1])
                elif line.startswith("VmHWM:"):
                    hwm_kib = int(line.split()[1])
                elif line.startswith("Threads:"):
                    threads = int(line.split()[1])
    except OSError:
        pass
    try:
        with open(f"/proc/{pid}/smaps_rollup", "r") as f:
            for line in f:
                if line.startswith("Pss:"):
                    pss_kib = int(line.split()[1])
                    break
    except OSError:
        pass
    return {
        "rss_kib": rss_kib,
        "hwm_kib": hwm_kib,
        "pss_kib": pss_kib,
        "threads": threads,
    }


def read_proc_cpu_ms(pid: int) -> dict:
    """Return daemon self CPU ms (utime+stime) and waited children CPU ms (cutime+cstime)."""
    try:
        with open(f"/proc/{pid}/stat", "r") as f:
            raw = f.read()
        # Handle comm field containing spaces/parens by finding last ')'
        rparen = raw.rfind(")")
        fields = raw[rparen + 2 :].split()
        # fields[0] is state (field 3 in proc(5)):
        # utime=14 -> idx 11, stime=15 -> idx 12, cutime=16 -> idx 13, cstime=17 -> idx 14
        utime = int(fields[11])
        stime = int(fields[12])
        cutime = int(fields[13])
        cstime = int(fields[14])
        self_ms = (utime + stime) * 1000.0 / CLK_TCK
        child_ms = (cutime + cstime) * 1000.0 / CLK_TCK
        return {
            "self_cpu_ms": round(self_ms, 2),
            "child_cpu_ms": round(child_ms, 2),
            "total_cpu_ms": round(self_ms + child_ms, 2),
        }
    except OSError:
        return {"self_cpu_ms": 0.0, "child_cpu_ms": 0.0, "total_cpu_ms": 0.0}


def cpu_delta(before: dict, after: dict) -> dict:
    s = max(0.0, after["self_cpu_ms"] - before["self_cpu_ms"])
    c = max(0.0, after["child_cpu_ms"] - before["child_cpu_ms"])
    return {
        "self_cpu_ms": round(s, 2),
        "child_cpu_ms": round(c, 2),
        "total_cpu_ms": round(s + c, 2),
    }


def nft_get_v4_elements(target: str) -> set[str]:
    if target == "rustban":
        cmd = ["/usr/sbin/nft", "-j", "list", "set", "inet", "rustban", "banned_v4"]
    else:
        cmd = ["/usr/sbin/nft", "-j", "list", "set", "inet", "f2b-table", "addr-set-sshd"]
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    if res.returncode != 0:
        return set()
    try:
        data = json.loads(res.stdout)
    except json.JSONDecodeError:
        return set()
    ips: set[str] = set()
    for item in data.get("nftables", []):
        st = item.get("set")
        if not st:
            continue
        for el in st.get("elem", []):
            if isinstance(el, str):
                ips.add(el)
            elif isinstance(el, dict) and "elem" in el:
                val = el["elem"].get("val")
                if isinstance(val, str):
                    ips.add(val)
    return ips


def wait_for_ip_in_nft(target: str, ip: str, timeout: float = 60.0, poll_s: float = 0.002) -> float:
    deadline = time.perf_counter() + timeout
    while time.perf_counter() < deadline:
        if ip in nft_get_v4_elements(target):
            return time.perf_counter()
        time.sleep(poll_s)
    raise RuntimeError(f"Timed out waiting for IP {ip} to appear in nftables ({target})")


def wait_for_count_in_nft(target: str, expected: int, timeout: float = 120.0, poll_s: float = 0.01) -> float:
    deadline = time.perf_counter() + timeout
    while time.perf_counter() < deadline:
        if len(nft_get_v4_elements(target)) >= expected:
            return time.perf_counter()
        time.sleep(poll_s)
    actual = len(nft_get_v4_elements(target))
    raise RuntimeError(f"Timed out waiting for {expected} IPs in nftables ({target}); got {actual}")


def wait_for_zero_in_nft(target: str, timeout: float = 60.0, poll_s: float = 0.05) -> float:
    deadline = time.perf_counter() + timeout
    while time.perf_counter() < deadline:
        if len(nft_get_v4_elements(target)) == 0:
            return time.perf_counter()
        time.sleep(poll_s)
    actual = len(nft_get_v4_elements(target))
    raise RuntimeError(f"Timed out waiting for bans to expire ({target}); still {actual} active")


def write_rustban_config(ban_time: str = "300s", find_time: str = "600s", max_retries: int = 3):
    cfg = f"""[global]
table_name = "rustban"
find_time = "{find_time}"
ban_time = "{ban_time}"
max_retries = {max_retries}
max_tracked_ips = 131072
include_default_ignores = true
ignore_self = true
ignore_ips = []

[jails.sshd]
enabled = true
log_path = "{LOG_PATH}"
fail_regex = [
  '{RUSTBAN_REGEX}'
]
"""
    with open(RUSTBAN_CFG, "w") as f:
        f.write(cfg)


def write_fail2ban_config(ban_time: int = 300, find_time: int = 600, max_retries: int = 3):
    # Clean previous fail2ban state/db/configs for deterministic runs
    for p in (F2B_SOCK, F2B_PID, F2B_DB, F2B_LOG):
        try:
            os.remove(p)
        except FileNotFoundError:
            pass
    for d in ("/etc/fail2ban/jail.d",):
        if os.path.isdir(d):
            for fn in os.listdir(d):
                try:
                    os.remove(os.path.join(d, fn))
                except OSError:
                    pass

    # Write custom single-regex filter matching rustban's exact regex
    with open("/etc/fail2ban/filter.d/bench-sshd.conf", "w") as f:
        f.write(f"[Definition]\nfailregex = {FAIL2BAN_REGEX}\nignoreregex =\n")

    # Configure fail2ban.local (minimal logging overhead, standard SQLite DB)
    with open("/etc/fail2ban/fail2ban.local", "w") as f:
        f.write(
            f"[Definition]\n"
            f"loglevel = WARNING\n"
            f"logtarget = {F2B_LOG}\n"
            f"socket = {F2B_SOCK}\n"
            f"pidfile = {F2B_PID}\n"
            f"dbfile = {F2B_DB}\n"
        )

    # Configure jail.local using pyinotify + official nftables allports drop action
    with open("/etc/fail2ban/jail.local", "w") as f:
        f.write(
            f"[DEFAULT]\n"
            f"enabled = false\n"
            f"ignoreip = 127.0.0.1/8 ::1\n"
            f"usedns = no\n"
            f"backend = pyinotify\n"
            f"banaction = nftables[type=allports, blocktype=drop]\n"
            f"bantime = {ban_time}\n"
            f"findtime = {find_time}\n"
            f"maxretry = {max_retries}\n\n"
            f"[sshd]\n"
            f"enabled = true\n"
            f"filter = bench-sshd\n"
            f"logpath = {LOG_PATH}\n"
        )


def reset_log_file():
    with open(LOG_PATH, "w") as f:
        f.write("")


def proc_has_open_file(pid: int, target_path: str) -> bool:
    fd_dir = f"/proc/{pid}/fd"
    try:
        for fd in os.listdir(fd_dir):
            try:
                if os.readlink(os.path.join(fd_dir, fd)) == target_path:
                    return True
            except OSError:
                pass
    except OSError:
        pass
    return False


class DaemonRunner:
    def __init__(self, target: str, ban_time_secs: int = 300):
        self.target = target
        self.ban_time_secs = ban_time_secs
        self.proc: subprocess.Popen | None = None
        self.pid: int = 0
        self.startup_ms: float = 0.0

    def start(self):
        flush_nft_all()
        reset_log_file()
        if self.target == "rustban":
            write_rustban_config(ban_time=f"{self.ban_time_secs}s")
            t0 = time.perf_counter()
            self.proc = subprocess.Popen(
                ["/usr/local/bin/rustban", "run", "-c", RUSTBAN_CFG],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self.pid = self.proc.pid
            # Wait until nft table exists AND tailer has opened LOG_PATH
            deadline = t0 + 15.0
            while time.perf_counter() < deadline:
                if self.proc.poll() is not None:
                    raise RuntimeError(f"rustban exited prematurely with {self.proc.returncode}")
                nft_ok = subprocess.run(
                    ["/usr/sbin/nft", "list", "table", "inet", "rustban"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                ).returncode == 0
                if nft_ok and proc_has_open_file(self.pid, LOG_PATH):
                    self.startup_ms = round((time.perf_counter() - t0) * 1000.0, 2)
                    return
                time.sleep(0.002)
            raise RuntimeError("Timed out waiting for rustban startup")
        else:
            write_fail2ban_config(ban_time=self.ban_time_secs)
            t0 = time.perf_counter()
            res = subprocess.run(
                ["/usr/bin/fail2ban-client", "-x", "start"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            if res.returncode != 0:
                raise RuntimeError(f"fail2ban-client start failed: {res.stdout} {res.stderr}")
            # Confirm jail sshd is loaded and get PID
            deadline = t0 + 15.0
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
                            self.startup_ms = round((time.perf_counter() - t0) * 1000.0, 2)
                            return
                    except (OSError, ValueError):
                        pass
                time.sleep(0.005)
            raise RuntimeError("Timed out waiting for fail2ban startup")

    def warmup_ban(self, ip: str = "198.51.100.250"):
        """Trigger 1 ban so nftables table/set is initialized before timed bursts."""
        ts = syslog_ts()
        with open(LOG_PATH, "a") as f:
            for p in range(3):
                f.write(fail_line(ip, 30000 + p, ts))
            f.flush()
            os.fsync(f.fileno())
        wait_for_ip_in_nft(self.target, ip, timeout=15.0, poll_s=0.005)

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
            # Ensure daemon exited
            if self.pid:
                for _ in range(50):
                    if not os.path.exists(f"/proc/{self.pid}"):
                        break
                    time.sleep(0.05)
                if os.path.exists(f"/proc/{self.pid}"):
                    try:
                        os.kill(self.pid, signal.SIGKILL)
                    except OSError:
                        pass
        flush_nft_all()


def bench_startup_and_idle(target: str) -> dict:
    # Measure 5 cold starts for median startup time, keep last one for idle memory check
    startups = []
    idle_mem = {}
    for i in range(5):
        d = DaemonRunner(target, ban_time_secs=300)
        d.start()
        startups.append(d.startup_ms)
        if i == 4:
            time.sleep(0.8)
            idle_mem = read_proc_mem(d.pid)
        d.stop()
    return {
        "cold_startup_ms_runs": startups,
        "cold_startup_ms_median": round(statistics.median(startups), 2),
        "cold_startup_ms_min": round(min(startups), 2),
        "idle_memory": idle_mem,
    }


def bench_single_ip_latency(target: str, trials: int = 20) -> dict:
    d = DaemonRunner(target, ban_time_secs=300)
    d.start()
    try:
        d.warmup_ban("198.51.100.250")
        time.sleep(0.2)
        latencies = []
        for i in range(1, trials + 1):
            ip = f"198.51.100.{i}"
            ts = syslog_ts()
            t0 = time.perf_counter()
            with open(LOG_PATH, "a") as f:
                f.write(fail_line(ip, 41000, ts))
                f.write(fail_line(ip, 41001, ts))
                f.write(fail_line(ip, 41002, ts))
                f.flush()
            t1 = wait_for_ip_in_nft(target, ip, timeout=15.0, poll_s=0.001)
            latencies.append(round((t1 - t0) * 1000.0, 2))
            time.sleep(0.05)
        s = sorted(latencies)
        p95_idx = min(len(s) - 1, int(round(0.95 * (len(s) - 1))))
        return {
            "trials": trials,
            "min_ms": s[0],
            "p50_ms": round(statistics.median(s), 2),
            "mean_ms": round(statistics.mean(s), 2),
            "p95_ms": s[p95_idx],
            "max_ms": s[-1],
        }
    finally:
        d.stop()


def bench_noise_throughput(target: str, num_lines: int = 100_000) -> dict:
    d = DaemonRunner(target, ban_time_secs=300)
    d.start()
    try:
        d.warmup_ban("198.51.100.250")
        time.sleep(0.2)

        # Pre-build payload in RAM so disk/Python generation overhead isn't charged to the daemon
        ts = syslog_ts()
        block = "".join(t.format(ts=ts) + "\n" for t in NOISE_TEMPLATES)
        reps = num_lines // len(NOISE_TEMPLATES)
        sentinel = "198.51.100.200"
        payload = (block * reps) + (fail_line(sentinel, 42000, ts) * 3)
        payload_bytes = len(payload.encode("utf-8"))

        cpu_before = read_proc_cpu_ms(d.pid)
        t0 = time.perf_counter()
        with open(LOG_PATH, "a") as f:
            f.write(payload)
            f.flush()
        t1 = wait_for_ip_in_nft(target, sentinel, timeout=180.0, poll_s=0.005)
        cpu_after = read_proc_cpu_ms(d.pid)
        mem = read_proc_mem(d.pid)

        wall_s = t1 - t0
        return {
            "lines": num_lines,
            "payload_mb": round(payload_bytes / (1024 * 1024), 2),
            "wall_secs": round(wall_s, 4),
            "lines_per_sec": round(num_lines / wall_s, 1),
            "memory": mem,
            "cpu": cpu_delta(cpu_before, cpu_after),
        }
    finally:
        d.stop()


def bench_attack_burst_and_cli_status(target: str, num_bans: int = 200, num_scanners: int = 5000, num_noise: int = 10000) -> dict:
    d = DaemonRunner(target, ban_time_secs=300)
    d.start()
    try:
        d.warmup_ban("198.51.100.250")
        time.sleep(0.2)

        ts = syslog_ts()
        lines = []
        noise_cycle = [t.format(ts=ts) + "\n" for t in NOISE_TEMPLATES]
        # Interleave noise, 1-failure scanners, and 3-failure attackers
        for i in range(num_noise):
            lines.append(noise_cycle[i % len(noise_cycle)])
        for i in range(num_scanners):
            ip = f"198.18.{(i // 250) % 250}.{(i % 250) + 1}"
            lines.append(fail_line(ip, 45000 + (i % 1000), ts))
        for i in range(1, num_bans + 1):
            ip = f"203.0.113.{i}"
            lines.append(fail_line(ip, 46000, ts))
            lines.append(fail_line(ip, 46001, ts))
            lines.append(fail_line(ip, 46002, ts))
        payload = "".join(lines)
        total_lines = len(lines)

        cpu_before = read_proc_cpu_ms(d.pid)
        t0 = time.perf_counter()
        with open(LOG_PATH, "a") as f:
            f.write(payload)
            f.flush()
        # 1 warmup + num_bans active bans
        t1 = wait_for_count_in_nft(target, 1 + num_bans, timeout=180.0, poll_s=0.01)
        cpu_after = read_proc_cpu_ms(d.pid)
        mem = read_proc_mem(d.pid)

        wall_s = t1 - t0

        # Sub-benchmark: CLI status query latency while 201 bans are active
        status_cmd = (
            ["/usr/local/bin/rustban", "status"]
            if target == "rustban"
            else ["/usr/bin/fail2ban-client", "status", "sshd"]
        )
        cli_times = []
        for _ in range(10):
            ct0 = time.perf_counter()
            run_cmd(status_cmd)
            cli_times.append(round((time.perf_counter() - ct0) * 1000.0, 2))

        return {
            "total_lines": total_lines,
            "bans_triggered": num_bans,
            "unique_scanners_tracked": num_scanners,
            "noise_lines": num_noise,
            "wall_secs": round(wall_s, 4),
            "bans_per_sec": round(num_bans / wall_s, 1),
            "memory": mem,
            "cpu": cpu_delta(cpu_before, cpu_after),
            "cli_status_ms_median": round(statistics.median(cli_times), 2),
            "cli_status_ms_min": round(min(cli_times), 2),
        }
    finally:
        d.stop()


def bench_spoofed_ip_flood(target: str, unique_ips: int = 50_000) -> dict:
    d = DaemonRunner(target, ban_time_secs=300)
    d.start()
    try:
        d.warmup_ban("198.51.100.250")
        time.sleep(0.2)

        ts = syslog_ts()
        lines = []
        for i in range(unique_ips):
            b2 = (i // 250) % 250
            b3 = (i % 250) + 1
            b1 = 18 + (i // (250 * 250))
            ip = f"198.{b1}.{b2}.{b3}"
            lines.append(fail_line(ip, 50000 + (i % 1000), ts))
        sentinel = "198.51.100.201"
        lines.extend([fail_line(sentinel, 51000 + p, ts) for p in range(3)])
        payload = "".join(lines)

        cpu_before = read_proc_cpu_ms(d.pid)
        t0 = time.perf_counter()
        with open(LOG_PATH, "a") as f:
            f.write(payload)
            f.flush()
        t1 = wait_for_ip_in_nft(target, sentinel, timeout=180.0, poll_s=0.005)
        cpu_after = read_proc_cpu_ms(d.pid)
        mem = read_proc_mem(d.pid)

        wall_s = t1 - t0
        return {
            "unique_ips": unique_ips,
            "wall_secs": round(wall_s, 4),
            "ips_per_sec": round(unique_ips / wall_s, 1),
            "memory": mem,
            "cpu": cpu_delta(cpu_before, cpu_after),
        }
    finally:
        d.stop()


def bench_ban_expiration(target: str, num_bans: int = 100, ban_time_secs: int = 5) -> dict:
    d = DaemonRunner(target, ban_time_secs=ban_time_secs)
    d.start()
    try:
        ts = syslog_ts()
        lines = []
        for i in range(1, num_bans + 1):
            ip = f"203.0.113.{i}"
            lines.append(fail_line(ip, 47000, ts))
            lines.append(fail_line(ip, 47001, ts))
            lines.append(fail_line(ip, 47002, ts))
        with open(LOG_PATH, "a") as f:
            f.write("".join(lines))
            f.flush()

        # Wait until all 100 bans are installed in kernel nftables
        wait_for_count_in_nft(target, num_bans, timeout=60.0, poll_s=0.01)

        # Now measure strictly the EXPIRATION phase (zero new log lines!)
        cpu_before = read_proc_cpu_ms(d.pid)
        t0 = time.perf_counter()
        t1 = wait_for_zero_in_nft(target, timeout=60.0, poll_s=0.05)
        # Brief settle so fail2ban finishes reaping final unban child if any
        time.sleep(0.3)
        cpu_after = read_proc_cpu_ms(d.pid)
        mem = read_proc_mem(d.pid)

        return {
            "bans_expired": num_bans,
            "configured_ban_time_secs": ban_time_secs,
            "drain_wall_secs": round(t1 - t0, 3),
            "expiration_cpu": cpu_delta(cpu_before, cpu_after),
            "post_expiry_memory": mem,
        }
    finally:
        d.stop()


def bench_offline_regex(target: str, total_lines: int = 100_000, match_lines: int = 10_000) -> dict:
    # Ensure config/filter files exist
    if target == "rustban":
        write_rustban_config()
    else:
        write_fail2ban_config()

    offline_log = "/tmp/offline-100k.log"
    ts = syslog_ts()
    noise_cycle = [t.format(ts=ts) + "\n" for t in NOISE_TEMPLATES]
    noise_count = total_lines - match_lines
    stride = total_lines // match_lines  # every 10th line is a match

    with open(offline_log, "w") as f:
        m_idx = 0
        n_idx = 0
        for i in range(total_lines):
            if i % stride == 0 and m_idx < match_lines:
                ip = f"203.0.113.{(m_idx % 200) + 1}"
                f.write(fail_line(ip, 40000 + (m_idx % 5000), ts))
                m_idx += 1
            else:
                f.write(noise_cycle[n_idx % len(noise_cycle)])
                n_idx += 1

    if target == "rustban":
        cmd = ["/usr/local/bin/rustban", "test", "-c", RUSTBAN_CFG, offline_log]
    else:
        cmd = ["/usr/bin/fail2ban-regex", offline_log, "/etc/fail2ban/filter.d/bench-sshd.conf"]

    runs = []
    matched_verified = 0
    for _ in range(3):
        t0 = time.perf_counter()
        res = run_cmd(cmd)
        elapsed = time.perf_counter() - t0
        runs.append(round(elapsed, 4))
        out = res.stdout + "\n" + res.stderr
        if target == "rustban":
            m = re.search(r"matches=(\d+)", out)
            matched_verified = int(m.group(1)) if m else -1
        else:
            m = re.search(r"Lines:\s+\d+\s+lines,.*?(\d+)\s+matched", out)
            matched_verified = int(m.group(1)) if m else -1

    if matched_verified != match_lines:
        raise RuntimeError(f"Offline regex match count mismatch for {target}: expected {match_lines}, got {matched_verified}")

    med = statistics.median(runs)
    return {
        "total_lines": total_lines,
        "matched_lines": matched_verified,
        "runs_secs": runs,
        "median_secs": round(med, 4),
        "lines_per_sec": round(total_lines / med, 1),
    }


def collect_versions(target: str) -> dict:
    nft_ver = run_cmd(["/usr/sbin/nft", "--version"]).stdout.strip()
    if target == "rustban":
        ver = run_cmd(["/usr/local/bin/rustban", "--version"]).stdout.strip()
        bin_bytes = os.path.getsize("/usr/local/bin/rustban")
        return {
            "tool_version": ver,
            "nft_version": nft_ver,
            "binary_bytes": bin_bytes,
        }
    else:
        ver = run_cmd(["/usr/bin/fail2ban-server", "--version"]).stdout.strip()
        py_ver = run_cmd(["/usr/bin/python3", "--version"]).stdout.strip()
        # Sum installed size of fail2ban + python3 runtime packages via dpkg-query
        dpkg = run_cmd([
            "dpkg-query", "-W", "-f=${Installed-Size}\n",
            "fail2ban", "python3", "python3-minimal", "python3.11", "python3.11-minimal",
            "libpython3.11-stdlib", "libpython3.11-minimal", "python3-pyinotify",
        ], check=False)
        pkg_kib = sum(int(x) for x in dpkg.stdout.split() if x.isdigit())
        return {
            "tool_version": f"{ver} ({py_ver})",
            "nft_version": nft_ver,
            "installed_pkg_bytes": pkg_kib * 1024,
        }


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ("rustban", "fail2ban"):
        print("Usage: bench_harness.py <rustban|fail2ban>", file=sys.stderr)
        sys.exit(2)

    target = sys.argv[1]
    sys.stderr.write(f"[bench:{target}] collecting versions...\n")
    result = {
        "target": target,
        "meta": collect_versions(target),
    }

    sys.stderr.write(f"[bench:{target}] 1/7 cold startup & idle memory...\n")
    result["startup_and_idle"] = bench_startup_and_idle(target)

    sys.stderr.write(f"[bench:{target}] 2/7 single-IP detection-to-kernel-ban latency (20 trials)...\n")
    result["single_ip_latency"] = bench_single_ip_latency(target, trials=20)

    sys.stderr.write(f"[bench:{target}] 3/7 noise log ingestion throughput (100,000 lines)...\n")
    result["noise_throughput_100k"] = bench_noise_throughput(target, num_lines=100_000)

    sys.stderr.write(f"[bench:{target}] 4/7 distributed attack burst (200 bans + 5,000 scanners + 10,000 noise) & CLI status...\n")
    result["attack_burst_200"] = bench_attack_burst_and_cli_status(target, num_bans=200, num_scanners=5000, num_noise=10000)

    sys.stderr.write(f"[bench:{target}] 5/7 spoofed-IP flood (50,000 unique IPs x 1 failure)...\n")
    result["spoofed_ip_flood_50k"] = bench_spoofed_ip_flood(target, unique_ips=50_000)

    sys.stderr.write(f"[bench:{target}] 6/7 ban expiration overhead (100 bans x 5s TTL)...\n")
    result["ban_expiration_100"] = bench_ban_expiration(target, num_bans=100, ban_time_secs=5)

    sys.stderr.write(f"[bench:{target}] 7/7 offline regex scanner (100,000 lines, 10,000 matches)...\n")
    result["offline_regex_100k"] = bench_offline_regex(target, total_lines=100_000, match_lines=10_000)

    sys.stderr.write(f"[bench:{target}] done!\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
