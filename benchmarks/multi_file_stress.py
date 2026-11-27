#!/usr/bin/env python3
"""
Multi-File Distributed Scan Stress Test for rustban.

Simulates a coordinated botnet scanning 8 independent services simultaneously
(8 separate log files -> 8 concurrent file-tailer threads + 1 main event loop):
  - Phase 1 (Flood): 8 concurrent writer threads blast 8 files simultaneously with:
      * 10,000 unique scanner IPs per file (80,000 total unique IPs, 1 failure each)
      * 10,000 benign noise lines per file (80,000 total noise lines)
      * 50 real attackers per file x 3 failures (400 real kernel nftables bans)
      * 1 final sentinel attacker per file x 3 failures (8 sentinels -> 408 total bans)
    Total: 161,224 log lines across 8 files, 80,408 unique IPs, 408 kernel bans.
    Each jail caps FailureTracker at max_tracked_ips = 5,000 (40,000 live entries total),
    forcing continuous O(1) eviction churn across all 8 jails.
  - Phase 2 (Post-Scan Prune & Responsiveness): Wait past find_time (5s), trigger
    FailureTracker::prune() across all 8 jails, record post-prune VmRSS / PSS, and verify
    a fresh live ban still lands promptly in kernel nftables.
"""

import json
import os
import signal
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor

CLK_TCK = os.sysconf(os.sysconf_names["SC_CLK_TCK"])

NUM_JAILS = 8
SCANNERS_PER_JAIL = 10_000
NOISE_PER_JAIL = 10_000
ATTACKERS_PER_JAIL = 50
MAX_TRACKED_PER_JAIL = 5_000
FIND_TIME_SECS = 5

SERVICES = [
    (
        "sshd",
        r"Failed password for (?:invalid user )?\S+ from <HOST> port \d+ ssh2$",
        "Nov 27 08:00:00 host sshd[1001]: Failed password for invalid user root from {ip} port 41234 ssh2\n",
        "Nov 27 08:00:00 host sshd[1002]: Accepted publickey for deploy from 198.51.100.250 port 50001 ssh2\n",
    ),
    (
        "nginx-auth",
        r"client: <HOST>, server: .*, request: \".*\", host: \".*\" \[AUTH_FAIL\]$",
        "2026/11/27 08:00:00 [error] 10#10: *1 user \"admin\" password mismatch, client: {ip}, server: example.com, request: \"POST /login HTTP/1.1\", host: \"example.com\" [AUTH_FAIL]\n",
        "2026/11/27 08:00:00 [info] 10#10: *2 healthcheck ok 198.51.100.250 GET /healthz 200\n",
    ),
    (
        "nginx-scan",
        r"^<HOST> - - \[[^\]]+\] \"(?:GET|POST) /(?:\.env|wp-login\.php|phpmyadmin) HTTP/1\.[01]\" 404 ",
        "{ip} - - [27/Nov/2026:08:00:00 +0000] \"GET /.env HTTP/1.1\" 404 153 \"-\" \"scanner/1.0\"\n",
        "198.51.100.250 - - [27/Nov/2026:08:00:00 +0000] \"GET /assets/app.js HTTP/1.1\" 200 4096 \"-\" \"Mozilla/5.0\"\n",
    ),
    (
        "postfix",
        r"warning: unknown\[<HOST>\]: SASL LOGIN authentication failed:",
        "Nov 27 08:00:00 mail postfix/smtpd[2001]: warning: unknown[{ip}]: SASL LOGIN authentication failed: UGFzc3dvcmQ6\n",
        "Nov 27 08:00:00 mail postfix/qmgr[2002]: 4A1B2C3D: from=<noreply@example.com>, size=1204, nrcpt=1 (queue active)\n",
    ),
    (
        "dovecot",
        r"imap-login: Aborted login \(auth failed, \d+ attempts\): user=<[^>]*>, method=PLAIN, rip=<HOST>,",
        "Nov 27 08:00:00 mail dovecot: imap-login: Aborted login (auth failed, 1 attempts): user=<admin>, method=PLAIN, rip={ip}, lip=10.0.0.1, TLS\n",
        "Nov 27 08:00:00 mail dovecot: imap(deploy): Logged out in=120 out=980\n",
    ),
    (
        "caddy",
        r"\"remote_ip\":\"<HOST>\".*\"status\":401",
        "{{\"ts\":1795742400,\"logger\":\"http.log.access\",\"request\":{{\"remote_ip\":\"{ip}\",\"uri\":\"/admin\"}},\"status\":401}}\n",
        "{{\"ts\":1795742400,\"logger\":\"http.log.access\",\"request\":{{\"remote_ip\":\"198.51.100.250\",\"uri\":\"/\"}},\"status\":200}}\n",
    ),
    (
        "traefik",
        r"^<HOST> - \S+ \[[^\]]+\] \"POST /api/v1/token HTTP/2\.0\" 403 ",
        "{ip} - api [27/Nov/2026:08:00:00 +0000] \"POST /api/v1/token HTTP/2.0\" 403 42\n",
        "198.51.100.250 - api [27/Nov/2026:08:00:00 +0000] \"GET /api/v1/status HTTP/2.0\" 200 128\n",
    ),
    (
        "custom-api",
        r"AUTH_REJECTED src=<HOST> reason=bad_key$",
        "2026-11-27T08:00:00Z WARN api-gw AUTH_REJECTED src={ip} reason=bad_key\n",
        "2026-11-27T08:00:00Z INFO api-gw REQ_OK src=198.51.100.250 latency_ms=2\n",
    ),
]

CFG_PATH = "/tmp/rustban-stress.toml"


def log_path(idx: int) -> str:
    return f"/tmp/stress-jail-{idx}.log"


def flush_nft():
    subprocess.run(
        ["/usr/sbin/nft", "flush", "ruleset"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def read_proc_mem(pid: int) -> dict:
    rss_kib = hwm_kib = threads = pss_kib = 0
    with open(f"/proc/{pid}/status") as f:
        for line in f:
            if line.startswith("VmRSS:"):
                rss_kib = int(line.split()[1])
            elif line.startswith("VmHWM:"):
                hwm_kib = int(line.split()[1])
            elif line.startswith("Threads:"):
                threads = int(line.split()[1])
    try:
        with open(f"/proc/{pid}/smaps_rollup") as f:
            for line in f:
                if line.startswith("Pss:"):
                    pss_kib = int(line.split()[1])
                    break
    except OSError:
        pass
    return {"rss_kib": rss_kib, "hwm_kib": hwm_kib, "pss_kib": pss_kib, "threads": threads}


def read_proc_cpu_ms(pid: int) -> dict:
    with open(f"/proc/{pid}/stat") as f:
        raw = f.read()
    rparen = raw.rfind(")")
    fields = raw[rparen + 2 :].split()
    self_ms = (int(fields[11]) + int(fields[12])) * 1000.0 / CLK_TCK
    child_ms = (int(fields[13]) + int(fields[14])) * 1000.0 / CLK_TCK
    return {
        "self_cpu_ms": round(self_ms, 2),
        "child_cpu_ms": round(child_ms, 2),
        "total_cpu_ms": round(self_ms + child_ms, 2),
    }


def cpu_delta(before: dict, after: dict) -> dict:
    s = max(0.0, after["self_cpu_ms"] - before["self_cpu_ms"])
    c = max(0.0, after["child_cpu_ms"] - before["child_cpu_ms"])
    return {"self_cpu_ms": round(s, 2), "child_cpu_ms": round(c, 2), "total_cpu_ms": round(s + c, 2)}


def nft_banned_v4() -> set[str]:
    p = subprocess.run(
        ["/usr/sbin/nft", "-j", "list", "set", "inet", "rustban", "banned_v4"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    if p.returncode != 0:
        return set()
    data = json.loads(p.stdout)
    out = set()
    for item in data.get("nftables", []):
        s = item.get("set")
        if s and "elem" in s:
            for e in s["elem"]:
                if isinstance(e, dict) and "elem" in e:
                    out.add(str(e["elem"]["val"]))
                elif isinstance(e, str):
                    out.add(e)
    return out


def proc_open_fds(pid: int) -> set[str]:
    opened = set()
    try:
        for fd in os.listdir(f"/proc/{pid}/fd"):
            try:
                opened.add(os.readlink(f"/proc/{pid}/fd/{fd}"))
            except OSError:
                pass
    except OSError:
        pass
    return opened


def write_config():
    lines = [
        "[global]",
        'table_name = "rustban"',
        'ignore_ips = ["127.0.0.0/8", "::1", "198.51.100.0/24"]',
        "ignore_self = true",
        'ban_time = "300s"',
        f'find_time = "{FIND_TIME_SECS}s"',
        "max_retries = 3",
        f"max_tracked_ips = {MAX_TRACKED_PER_JAIL}",
        "",
    ]
    for i, (name, regex, _, _) in enumerate(SERVICES):
        lines.extend(
            [
                f"[jails.{name}]",
                "enabled = true",
                f'log_path = "{log_path(i)}"',
                f"fail_regex = ['{regex}']",
                "",
            ]
        )
    with open(CFG_PATH, "w") as f:
        f.write("\n".join(lines))


def build_payload(jail_idx: int) -> tuple[bytes, str]:
    _, _, fail_tmpl, noise_tmpl = SERVICES[jail_idx]
    chunks: list[str] = []

    attacker_idx = 0
    for n in range(SCANNERS_PER_JAIL):
        hi = (n // 250) + 1
        lo = (n % 250) + 1
        scanner_ip = f"11.{jail_idx + 1}.{hi}.{lo}"
        chunks.append(fail_tmpl.format(ip=scanner_ip))
        chunks.append(noise_tmpl)

        if n % (SCANNERS_PER_JAIL // ATTACKERS_PER_JAIL) == 0 and attacker_idx < ATTACKERS_PER_JAIL:
            attacker_idx += 1
            atk_ip = f"44.{jail_idx + 1}.1.{attacker_idx}"
            line = fail_tmpl.format(ip=atk_ip)
            chunks.append(line)
            chunks.append(line)
            chunks.append(line)

    sentinel_ip = f"44.{jail_idx + 1}.250.1"
    sline = fail_tmpl.format(ip=sentinel_ip)
    chunks.append(sline)
    chunks.append(sline)
    chunks.append(sline)

    return "".join(chunks).encode("utf-8"), sentinel_ip


def main():
    flush_nft()
    write_config()
    for i in range(NUM_JAILS):
        with open(log_path(i), "w"):
            pass

    payloads = [build_payload(i) for i in range(NUM_JAILS)]
    sentinels = {s for _, s in payloads}
    expected_bans = NUM_JAILS * (ATTACKERS_PER_JAIL + 1)
    total_lines = sum(p.count(b"\n") for p, _ in payloads)

    proc = subprocess.Popen(
        ["/usr/local/bin/rustban", "run", "-c", CFG_PATH],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 15.0
        target_paths = {log_path(i) for i in range(NUM_JAILS)}
        while time.monotonic() < deadline:
            if target_paths.issubset(proc_open_fds(proc.pid)):
                break
            time.sleep(0.02)
        else:
            raise RuntimeError("rustban did not open all 8 log files in time")
        time.sleep(0.15)

        idle_mem = read_proc_mem(proc.pid)
        cpu_before = read_proc_cpu_ms(proc.pid)

        barrier = threading.Barrier(NUM_JAILS)

        def write_file(idx: int):
            data, _ = payloads[idx]
            barrier.wait()
            with open(log_path(idx), "ab", buffering=0) as f:
                mv = memoryview(data)
                step = 65_536
                for off in range(0, len(mv), step):
                    f.write(mv[off : off + step])

        t0 = time.perf_counter()
        with ThreadPoolExecutor(max_workers=NUM_JAILS) as pool:
            futs = [pool.submit(write_file, i) for i in range(NUM_JAILS)]
            for fut in futs:
                fut.result()
        write_done = time.perf_counter() - t0

        deadline = time.perf_counter() + 60.0
        banned = set()
        while time.perf_counter() < deadline:
            banned = nft_banned_v4()
            if sentinels.issubset(banned) and len(banned) >= expected_bans:
                break
            time.sleep(0.005)
        wall_secs = time.perf_counter() - t0
        cpu_after = read_proc_cpu_ms(proc.pid)
        peak_mem = read_proc_mem(proc.pid)

        if len(banned) < expected_bans:
            raise RuntimeError(f"missed bans: got {len(banned)}/{expected_bans}")

        # Phase 2: Wait past find_time, trigger FailureTracker::prune() in all 8 jails, verify live ban
        time.sleep(FIND_TIME_SECS + 0.6)
        for i in range(NUM_JAILS):
            _, _, fail_tmpl, _ = SERVICES[i]
            with open(log_path(i), "a") as f:
                f.write(fail_tmpl.format(ip=f"55.{i + 1}.99.99"))
        time.sleep(0.6)
        post_prune_mem = read_proc_mem(proc.pid)

        _, _, fail_tmpl, _ = SERVICES[0]
        probe_ip = "44.99.99.99"
        t_probe = time.perf_counter()
        with open(log_path(0), "a") as f:
            for _ in range(3):
                f.write(fail_tmpl.format(ip=probe_ip))
        while probe_ip not in nft_banned_v4():
            if time.perf_counter() - t_probe > 10.0:
                raise RuntimeError("post-prune probe ban timed out")
            time.sleep(0.002)
        post_prune_ban_ms = round((time.perf_counter() - t_probe) * 1000.0, 2)

        res = {
            "jails": NUM_JAILS,
            "total_lines": total_lines,
            "unique_scanner_ips": NUM_JAILS * SCANNERS_PER_JAIL,
            "expected_bans": expected_bans,
            "actual_bans": len(banned),
            "write_secs": round(write_done, 4),
            "wall_secs": round(wall_secs, 4),
            "lines_per_sec": round(total_lines / wall_secs, 1),
            "cpu": cpu_delta(cpu_before, cpu_after),
            "idle_mem": idle_mem,
            "flood_mem": peak_mem,
            "post_prune_mem": post_prune_mem,
            "post_prune_ban_ms": post_prune_ban_ms,
        }
        print(json.dumps(res, indent=2))
    finally:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        flush_nft()


if __name__ == "__main__":
    main()
