# Security Policy

## Supported Versions

Security fixes are applied to the latest release on the `main` branch.

| Version | Supported |
| --- | --- |
| Latest (`main`) | Yes |
| Older releases | No |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, report them privately using GitHub Security Advisories:

- https://github.com/marcelo-lipienski/rustban/security/advisories/new

Please include:
- A clear description of the vulnerability and potential impact (e.g., self-lockout, IP spoofing, firewall syntax injection, ReDoS, memory exhaustion, or privilege escalation).
- Minimal reproduction steps, sample log lines, or configuration (`rustban.toml`).
- Your `rustban --version`, Linux kernel version, and `nft --version`.

You can expect an initial acknowledgement within 72 hours and coordinated disclosure once a fix and regression test are prepared.

## Automated Security Verification

Every push runs unit/integration exploit tests (`tests/security_exploits.rs`) and live Docker `nftables` exploit checks (`./scripts/test-docker.sh`). Every release runs `cargo audit` and the 8-vector live security gate (`./scripts/security-check-docker.sh`).
