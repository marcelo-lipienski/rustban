# Live Security & Exploit Comparison: `rustban` vs `fail2ban`

Reproducible head-to-head live exploit test suite executed inside isolated `debian:bookworm-slim` containers (`--cap-add=NET_ADMIN`, `nftables 1.0.6`, Linux `6.17.0-40-generic`).

> Re-run anytime with `./scripts/security-compare-docker.sh`. Raw JSON output is stored in [`security_results.json`](./security_results.json).

**Configuration under test (out-of-the-box defaults):**
- **`rustban`**: shipped `sshd` regexes from `rustban.toml.example`, default `include_default_ignores = true`, `ignore_self = true`, `prerouting @ raw` `nftables` table.
- **`fail2ban`**: official Debian Bookworm `Fail2Ban v1.0.2`, stock `/etc/fail2ban/filter.d/sshd.conf`, default `ignoreip`, `banaction = nftables[type=allports, blocktype=drop]`, `backend = pyinotify`.

## Summary Matrix (`rustban`: 8/8 protected · `fail2ban`: 3/8 protected)

| Exploit / Attack Scenario | `rustban` | `fail2ban` (stock Debian) |
|---|---|---|
| 1. Host Self-IP Auto-Protection (Log Flood) | **PROTECTED** | **PROTECTED** |
| 2. Manual / Forced CLI Self-Lockout Defense | **PROTECTED** | **VULNERABLE** |
| 3. SSH Username Log-Injection IP Spoofing | **PROTECTED** | **PROTECTED** |
| 4. Special / Broadcast / Non-Routable IP Protection | **PROTECTED** | **VULNERABLE** |
| 5. Shell & `nftables` Syntax Injection via Logs | **PROTECTED** | **PARTIAL** |
| 6. IPv6 `/64` Host-Bit Rotation Evasion | **PROTECTED** | **VULNERABLE** |
| 7. Cross-Service (TCP/UDP) & Established-Session Kill | **PROTECTED** | **VULNERABLE** |
| 8. ReDoS & 256 KiB Binary Garbage Log DoS | **PROTECTED** | **PROTECTED** |

---

## Observed Evidence

### 1. Host Self-IP Auto-Protection (Log Flood)
- **`rustban`** (**PROTECTED**): Host interface IP 172.17.0.2 auto-protected (0 bans)
- **`fail2ban`** (**PROTECTED**): Host interface IP 172.17.0.2 auto-protected (0 bans)

### 2. Manual / Forced CLI Self-Lockout Defense
- **`rustban`** (**PROTECTED**): CLI refused default ban=True; self-traffic to 172.17.0.2:2299 SURVIVED even after forced ban (kernel whitelist return)
- **`fail2ban`** (**VULNERABLE**): SELF-LOCKOUT: manual CLI ban on 172.17.0.2 dropped host's own traffic to 172.17.0.2:2299!

### 3. SSH Username Log-Injection IP Spoofing
- **`rustban`** (**PROTECTED**): Victim 203.0.113.1 safe; real attacker 198.51.100.77 accurately banned
- **`fail2ban`** (**PROTECTED**): Victim 203.0.113.1 safe; real attacker 198.51.100.77 accurately banned

### 4. Special / Broadcast / Non-Routable IP Protection
- **`rustban`** (**PROTECTED**): Zero special/non-routable/broadcast/loopback-adjacent addresses banned
- **`fail2ban`** (**VULNERABLE**): Banned special/non-routable address(es): ['0.0.0.0', '224.0.0.1', '255.255.255.255']

### 5. Shell & `nftables` Syntax Injection via Logs
- **`rustban`** (**PROTECTED**): Blocked all shell & nftables syntax injection payloads; firewall table intact and 0 false bans
- **`fail2ban`** (**PARTIAL**): No RCE or ruleset flush, but malformed injected host strings still triggered false bans: ['198.51.100.88', '203.0.113.9']

### 6. IPv6 `/64` Host-Bit Rotation Evasion
- **`rustban`** (**PROTECTED**): Blocked IPv6 host-bit rotation evasion -> banned ['2001:db8:cafe:1234::']
- **`fail2ban`** (**VULNERABLE**): EVADED: 0 IPv6 bans triggered across 5 failures from same /64 (tracks /128 individually)

### 7. Cross-Service (TCP/UDP) & Established-Session Kill
- **`rustban`** (**PROTECTED**): Dropped TCP 2222, TCP 8080, UDP 5353, AND severed already-established TCP 8080 session
- **`fail2ban`** (**VULNERABLE**): BYPASS: failed to drop UDP 5353 (TCP 2222=True, TCP 8080=True, UDP 5353=False, est_8080=True)

### 8. ReDoS & 256 KiB Binary Garbage Log DoS
- **`rustban`** (**PROTECTED**): Survived 50 ReDoS payloads + 256 KiB binary garbage and banned sentinel in 37.7 ms
- **`fail2ban`** (**PROTECTED**): Survived 50 ReDoS payloads + 256 KiB binary garbage and banned sentinel in 736.88 ms

