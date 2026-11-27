use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::ValueEnum;
use serde::Deserialize;

use crate::ip::IgnoreList;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Text,
    Json,
}

pub const DEFAULT_NFT_BIN: &str = "/usr/sbin/nft";
pub const DEFAULT_JOURNALCTL_BIN: &str = "/usr/bin/journalctl";
pub const DEFAULT_TABLE_NAME: &str = "rustban";
pub const DEFAULT_FIND_TIME_SECS: u64 = 600;
pub const DEFAULT_BAN_TIME_SECS: u64 = 3600;
pub const DEFAULT_BAN_TIME_MAX_SECS: u64 = 86_400;
pub const DEFAULT_BAN_TIME_WINDOW_SECS: u64 = 86_400;
pub const DEFAULT_MAX_RETRIES: usize = 5;
pub const DEFAULT_MAX_TRACKED_IPS: usize = 65_536;
pub const DEFAULT_MAX_LINE_BYTES: usize = 4096;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    #[serde(default)]
    global: RawGlobal,
    #[serde(default)]
    jails: BTreeMap<String, RawJail>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawGlobal {
    nft_bin: Option<PathBuf>,
    journalctl_bin: Option<PathBuf>,
    table_name: Option<String>,
    find_time: Option<String>,
    ban_time: Option<String>,
    ban_time_multiplier: Option<f64>,
    ban_time_max: Option<String>,
    ban_time_window: Option<String>,
    max_retries: Option<usize>,
    max_tracked_ips: Option<usize>,
    max_line_bytes: Option<usize>,
    include_default_ignores: Option<bool>,
    ignore_self: Option<bool>,
    ignore_self_refresh: Option<String>,
    log_format: Option<LogFormat>,
    #[serde(default)]
    ignore_ips: Vec<String>,
    #[serde(default)]
    ignore_interfaces: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawJail {
    #[serde(default = "default_true")]
    enabled: bool,
    log_path: Option<PathBuf>,
    systemd_unit: Option<String>,
    #[serde(default)]
    systemd_units: Vec<String>,
    syslog_identifier: Option<String>,
    find_time: Option<String>,
    ban_time: Option<String>,
    ban_time_multiplier: Option<f64>,
    ban_time_max: Option<String>,
    ban_time_window: Option<String>,
    max_retries: Option<usize>,
    max_tracked_ips: Option<usize>,
    #[serde(default)]
    fail_regex: Vec<String>,
    #[serde(default)]
    ignore_regex: Vec<String>,
    #[serde(default)]
    ignore_ips: Vec<String>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum LogSourceKind {
    File(PathBuf),
    Journald {
        units: Vec<String>,
        syslog_identifier: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BanEscalation {
    pub multiplier: f64,
    pub max_ban_time: Duration,
    pub window: Duration,
}

#[derive(Debug, Clone)]
pub struct JailConfig {
    pub name: String,
    pub source: LogSourceKind,
    pub find_time: Duration,
    pub ban_time: Duration,
    pub escalation: Option<BanEscalation>,
    pub max_retries: usize,
    pub max_tracked_ips: usize,
    pub fail_regex: Vec<String>,
    pub ignore_regex: Vec<String>,
    pub raw_ignore_ips: Vec<String>,
    pub ignore_ips: IgnoreList,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub nft_bin: PathBuf,
    pub journalctl_bin: PathBuf,
    pub table_name: String,
    pub max_line_bytes: usize,
    pub include_default_ignores: bool,
    pub ignore_self: bool,
    pub ignore_self_refresh: Option<Duration>,
    pub log_format: LogFormat,
    pub raw_global_ignore_ips: Vec<String>,
    pub ignore_interfaces: Vec<String>,
    pub global_ignores: IgnoreList,
    pub jails: Vec<JailConfig>,
}

impl Config {
    pub fn from_file(path: &Path) -> Result<Self, String> {
        Self::from_file_with_options(path, false)
    }

    pub fn from_file_with_options(path: &Path, include_disabled: bool) -> Result<Self, String> {
        let raw = fs::read_to_string(path)
            .map_err(|e| format!("failed to read config '{}': {e}", path.display()))?;
        Self::from_toml_str_with_options(&raw, include_disabled)
    }

    pub fn from_toml_str(input: &str) -> Result<Self, String> {
        Self::from_toml_str_with_options(input, false)
    }

    pub fn from_toml_str_with_options(input: &str, include_disabled: bool) -> Result<Self, String> {
        let parsed: RawConfig =
            toml::from_str(input).map_err(|e| format!("failed to parse TOML config: {e}"))?;

        let nft_bin = parsed
            .global
            .nft_bin
            .unwrap_or_else(|| PathBuf::from(DEFAULT_NFT_BIN));
        let journalctl_bin = parsed
            .global
            .journalctl_bin
            .unwrap_or_else(|| PathBuf::from(DEFAULT_JOURNALCTL_BIN));
        let table_name = parsed
            .global
            .table_name
            .unwrap_or_else(|| DEFAULT_TABLE_NAME.to_string());
        validate_nft_ident(&table_name, "global.table_name")?;

        let default_find_time = parse_opt_duration(
            parsed.global.find_time.as_deref(),
            Duration::from_secs(DEFAULT_FIND_TIME_SECS),
            "global.find_time",
        )?;
        let default_ban_time = parse_opt_duration(
            parsed.global.ban_time.as_deref(),
            Duration::from_secs(DEFAULT_BAN_TIME_SECS),
            "global.ban_time",
        )?;
        let default_ban_multiplier = validate_opt_multiplier(
            parsed.global.ban_time_multiplier,
            "global.ban_time_multiplier",
        )?;
        let default_ban_max = match parsed.global.ban_time_max.as_deref() {
            Some(s) => Some(parse_duration_nonzero(s, "global.ban_time_max")?),
            None => None,
        };
        let default_ban_window = match parsed.global.ban_time_window.as_deref() {
            Some(s) => Some(parse_duration_nonzero(s, "global.ban_time_window")?),
            None => None,
        };
        let default_max_retries = parsed.global.max_retries.unwrap_or(DEFAULT_MAX_RETRIES);
        if default_max_retries == 0 {
            return Err("global.max_retries must be >= 1".into());
        }
        let default_max_tracked = parsed
            .global
            .max_tracked_ips
            .unwrap_or(DEFAULT_MAX_TRACKED_IPS);
        if default_max_tracked == 0 {
            return Err("global.max_tracked_ips must be >= 1".into());
        }
        let max_line_bytes = parsed
            .global
            .max_line_bytes
            .unwrap_or(DEFAULT_MAX_LINE_BYTES);
        if max_line_bytes < 64 {
            return Err("global.max_line_bytes must be >= 64".into());
        }

        let include_defaults = parsed.global.include_default_ignores.unwrap_or(true);
        let ignore_self = parsed.global.ignore_self.unwrap_or(true);
        let ignore_self_refresh = match parsed.global.ignore_self_refresh.as_deref() {
            Some(s) => Some(parse_duration_nonzero(s, "global.ignore_self_refresh")?),
            None => None,
        };
        let log_format = parsed.global.log_format.unwrap_or_default();
        let mut ignore_interfaces = parsed.global.ignore_interfaces;
        for iface in &ignore_interfaces {
            validate_interface_name(iface, "global.ignore_interfaces")?;
        }
        ignore_interfaces.sort();
        ignore_interfaces.dedup();

        let raw_global_ignore_ips = parsed.global.ignore_ips;
        let global_ignores =
            IgnoreList::from_options(&raw_global_ignore_ips, include_defaults, ignore_self)?;

        let mut jails = Vec::new();
        for (name, raw_jail) in parsed.jails {
            if !include_disabled && !raw_jail.enabled {
                continue;
            }
            validate_comment_safe(&name, "jail name")?;

            if raw_jail.systemd_unit.is_some() && !raw_jail.systemd_units.is_empty() {
                return Err(format!(
                    "jail '{name}': specify either 'systemd_unit' or 'systemd_units', not both"
                ));
            }
            let mut units = raw_jail.systemd_units;
            if let Some(unit) = raw_jail.systemd_unit {
                units.push(unit);
            }
            let has_journald = !units.is_empty() || raw_jail.syslog_identifier.is_some();

            let source = match (raw_jail.log_path, has_journald) {
                (Some(path), false) => LogSourceKind::File(path),
                (None, true) => {
                    for u in &units {
                        validate_unit_name(u, &name)?;
                    }
                    units.sort();
                    units.dedup();
                    if let Some(ref ident) = raw_jail.syslog_identifier {
                        validate_syslog_identifier(ident, &name)?;
                    }
                    LogSourceKind::Journald {
                        units,
                        syslog_identifier: raw_jail.syslog_identifier,
                    }
                }
                (Some(_), true) => {
                    return Err(format!(
                        "jail '{name}': specify either 'log_path' or journald selectors ('systemd_unit'/'systemd_units'/'syslog_identifier'), not both"
                    ));
                }
                (None, false) => {
                    return Err(format!(
                        "jail '{name}': must specify 'log_path' or a journald selector ('systemd_unit', 'systemd_units', or 'syslog_identifier')"
                    ));
                }
            };

            if raw_jail.fail_regex.is_empty() {
                return Err(format!(
                    "jail '{name}': must specify at least one pattern in 'fail_regex'"
                ));
            }

            let find_time = parse_opt_duration(
                raw_jail.find_time.as_deref(),
                default_find_time,
                &format!("jails.{name}.find_time"),
            )?;
            let ban_time = parse_opt_duration(
                raw_jail.ban_time.as_deref(),
                default_ban_time,
                &format!("jails.{name}.ban_time"),
            )?;
            let jail_multiplier = match raw_jail.ban_time_multiplier {
                Some(m) => Some(validate_multiplier(
                    m,
                    &format!("jails.{name}.ban_time_multiplier"),
                )?),
                None => default_ban_multiplier,
            };
            let jail_ban_max = match raw_jail.ban_time_max.as_deref() {
                Some(s) => Some(parse_duration_nonzero(
                    s,
                    &format!("jails.{name}.ban_time_max"),
                )?),
                None => default_ban_max,
            };
            let jail_ban_window = match raw_jail.ban_time_window.as_deref() {
                Some(s) => Some(parse_duration_nonzero(
                    s,
                    &format!("jails.{name}.ban_time_window"),
                )?),
                None => default_ban_window,
            };
            let escalation = match jail_multiplier {
                Some(mult) if mult > 1.0 => {
                    let max_ban_time = jail_ban_max.unwrap_or_else(|| {
                        Duration::from_secs(DEFAULT_BAN_TIME_MAX_SECS).max(ban_time)
                    });
                    if max_ban_time < ban_time {
                        return Err(format!(
                            "jails.{name}.ban_time_max ({}s) must be >= ban_time ({}s)",
                            max_ban_time.as_secs(),
                            ban_time.as_secs()
                        ));
                    }
                    let window = jail_ban_window
                        .unwrap_or_else(|| Duration::from_secs(DEFAULT_BAN_TIME_WINDOW_SECS));
                    Some(BanEscalation {
                        multiplier: mult,
                        max_ban_time,
                        window,
                    })
                }
                _ => None,
            };
            let max_retries = raw_jail.max_retries.unwrap_or(default_max_retries);
            if max_retries == 0 {
                return Err(format!("jails.{name}.max_retries must be >= 1"));
            }
            let max_tracked_ips = raw_jail.max_tracked_ips.unwrap_or(default_max_tracked);
            if max_tracked_ips == 0 {
                return Err(format!("jails.{name}.max_tracked_ips must be >= 1"));
            }

            let mut jail_ignores = global_ignores.clone();
            if !raw_jail.ignore_ips.is_empty() {
                let extra = IgnoreList::from_strings(&raw_jail.ignore_ips, false)?;
                jail_ignores.extend_from(&extra);
            }

            jails.push(JailConfig {
                name,
                source,
                find_time,
                ban_time,
                escalation,
                max_retries,
                max_tracked_ips,
                fail_regex: raw_jail.fail_regex,
                ignore_regex: raw_jail.ignore_regex,
                raw_ignore_ips: raw_jail.ignore_ips,
                ignore_ips: jail_ignores,
            });
        }

        Ok(Config {
            nft_bin,
            journalctl_bin,
            table_name,
            max_line_bytes,
            include_default_ignores: include_defaults,
            ignore_self,
            ignore_self_refresh,
            log_format,
            raw_global_ignore_ips,
            ignore_interfaces,
            global_ignores,
            jails,
        })
    }
}

pub fn parse_duration_nonzero(s: &str, field: &str) -> Result<Duration, String> {
    let d = humantime::parse_duration(s.trim())
        .map_err(|e| format!("invalid duration for {field} ('{s}'): {e}"))?;
    if d.as_secs() == 0 {
        return Err(format!("{field} must be at least 1s (got '{s}')"));
    }
    Ok(d)
}

fn parse_opt_duration(
    raw: Option<&str>,
    default: Duration,
    field: &str,
) -> Result<Duration, String> {
    match raw {
        Some(s) => parse_duration_nonzero(s, field),
        None => Ok(default),
    }
}

fn validate_multiplier(val: f64, field: &str) -> Result<f64, String> {
    if !val.is_finite() || val < 1.0 {
        return Err(format!(
            "{field} must be a finite number >= 1.0 (use 1.0 or omit to disable; got {val})"
        ));
    }
    Ok(val)
}

fn validate_opt_multiplier(val: Option<f64>, field: &str) -> Result<Option<f64>, String> {
    match val {
        Some(v) => Ok(Some(validate_multiplier(v, field)?)),
        None => Ok(None),
    }
}

pub fn validate_nft_ident(name: &str, field: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 64 {
        return Err(format!("{field} must be 1..=64 characters"));
    }
    let mut chars = name.chars();
    let first = chars.next().unwrap();
    if !first.is_ascii_alphabetic() {
        return Err(format!("{field} must start with an ASCII letter: '{name}'"));
    }
    if !chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        return Err(format!(
            "{field} contains invalid characters (allowed: [A-Za-z0-9_-]): '{name}'"
        ));
    }
    const RESERVED: &[&str] = &[
        "add",
        "create",
        "delete",
        "destroy",
        "flush",
        "list",
        "reset",
        "table",
        "chain",
        "set",
        "map",
        "element",
        "rule",
        "inet",
        "ip",
        "ip6",
        "arp",
        "bridge",
        "netdev",
        "drop",
        "accept",
        "return",
        "reject",
        "raw",
        "filter",
        "prerouting",
        "input",
        "forward",
    ];
    if RESERVED.contains(&name.to_ascii_lowercase().as_str()) {
        return Err(format!(
            "{field} cannot be a reserved nftables keyword: '{name}'"
        ));
    }
    Ok(())
}

pub fn validate_comment_safe(value: &str, field: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 64 {
        return Err(format!("{field} must be 1..=64 characters"));
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':' | '/' | ' '))
    {
        return Err(format!(
            "{field} contains disallowed characters (allowed: [A-Za-z0-9_.:/ -]): '{value}'"
        ));
    }
    Ok(())
}

pub fn validate_interface_name(name: &str, field: &str) -> Result<(), String> {
    // Linux IFNAMSIZ is 16 bytes including NUL terminator => max 15 characters.
    // Disallow wildcards, quotes, whitespace, and leading '-' to prevent nft syntax injection.
    if name.is_empty() || name.len() > 15 || name.starts_with('-') {
        return Err(format!(
            "{field}: invalid interface name '{name}' (must be 1..=15 chars, not starting with '-')"
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':'))
    {
        return Err(format!(
            "{field}: interface name '{name}' contains disallowed characters (allowed: [A-Za-z0-9_.:-])"
        ));
    }
    Ok(())
}

fn validate_unit_name(unit: &str, jail: &str) -> Result<(), String> {
    if unit.is_empty() || unit.len() > 128 || unit.starts_with('-') {
        return Err(format!("jail '{jail}': invalid systemd_unit '{unit}'"));
    }
    if !unit
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@'))
    {
        return Err(format!(
            "jail '{jail}': invalid characters in systemd_unit '{unit}'"
        ));
    }
    Ok(())
}

fn validate_syslog_identifier(ident: &str, jail: &str) -> Result<(), String> {
    if ident.is_empty() || ident.len() > 128 || ident.starts_with('-') {
        return Err(format!(
            "jail '{jail}': invalid syslog_identifier '{ident}'"
        ));
    }
    if !ident
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@' | '/' | ':'))
    {
        return Err(format!(
            "jail '{jail}': invalid characters in syslog_identifier '{ident}'"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_config_with_defaults() {
        let toml = r#"
[global]
ban_time = "30m"
ignore_ips = ["10.0.0.0/8"]

[jails.sshd]
systemd_unit = "ssh.service"
fail_regex = ['Failed password for .* from <HOST>']

[jails.disabled_jail]
enabled = false
log_path = "/var/log/nope.log"
fail_regex = ['bad <HOST>']
"#;
        let cfg = Config::from_toml_str(toml).unwrap();
        assert_eq!(cfg.table_name, "rustban");
        assert_eq!(cfg.jails.len(), 1);
        assert_eq!(cfg.jails[0].name, "sshd");
        assert_eq!(cfg.jails[0].ban_time, Duration::from_secs(1800));
        assert_eq!(cfg.jails[0].find_time, Duration::from_secs(600));
        assert_eq!(cfg.jails[0].max_retries, 5);
    }

    #[test]
    fn rejects_both_file_and_unit() {
        let toml = r#"
[jails.bad]
log_path = "/var/log/a.log"
systemd_unit = "ssh.service"
fail_regex = ['from <HOST>']
"#;
        assert!(Config::from_toml_str(toml).is_err());
    }

    #[test]
    fn parses_multi_unit_and_syslog_identifier_and_include_disabled() {
        let toml = r#"
[jails.sshd]
systemd_units = ["sshd.service", "ssh.service", "ssh.service"]
syslog_identifier = "sshd"
fail_regex = ['Failed password for .+ from <HOST> port \d+ ssh2$']

[jails.ident_only]
enabled = false
syslog_identifier = "dropbear"
fail_regex = ['Bad password attempt for .+ from <HOST>:\d+$']
"#;
        let cfg = Config::from_toml_str(toml).unwrap();
        assert_eq!(cfg.jails.len(), 1);
        assert_eq!(
            cfg.jails[0].source,
            LogSourceKind::Journald {
                units: vec!["ssh.service".into(), "sshd.service".into()],
                syslog_identifier: Some("sshd".into()),
            }
        );

        let all = Config::from_toml_str_with_options(toml, true).unwrap();
        assert_eq!(all.jails.len(), 2);
        assert_eq!(
            all.jails[0].source,
            LogSourceKind::Journald {
                units: vec![],
                syslog_identifier: Some("dropbear".into()),
            }
        );
    }

    #[test]
    fn rejects_conflicting_or_malicious_journald_selectors() {
        let both_units = r#"
[jails.bad]
systemd_unit = "ssh.service"
systemd_units = ["sshd.service"]
fail_regex = ['from <HOST>$']
"#;
        assert!(Config::from_toml_str(both_units).is_err());

        let file_and_ident = r#"
[jails.bad]
log_path = "/var/log/auth.log"
syslog_identifier = "sshd"
fail_regex = ['from <HOST>$']
"#;
        assert!(Config::from_toml_str(file_and_ident).is_err());

        for bad_ident in ["--unit=foo", "sshd; id", "sshd $(whoami)", ""] {
            let toml = format!(
                "[jails.bad]\nsyslog_identifier = \"{bad_ident}\"\nfail_regex = ['from <HOST>$']\n"
            );
            assert!(
                Config::from_toml_str(&toml).is_err(),
                "should reject bad syslog_identifier: {bad_ident:?}"
            );
        }
    }

    #[test]
    fn parses_ban_escalation_inheritance_and_overrides() {
        let toml = r#"
[global]
ban_time = "10m"
ban_time_multiplier = 2.0
ban_time_max = "2h"
ban_time_window = "12h"

[jails.inherits]
log_path = "/tmp/a.log"
fail_regex = ['from <HOST>$']

[jails.disabled_escalation]
log_path = "/tmp/b.log"
ban_time_multiplier = 1.0
fail_regex = ['from <HOST>$']

[jails.custom]
log_path = "/tmp/c.log"
ban_time = "5m"
ban_time_multiplier = 3.0
ban_time_max = "1h"
fail_regex = ['from <HOST>$']
"#;
        let cfg = Config::from_toml_str(toml).unwrap();
        let by_name = |n: &str| cfg.jails.iter().find(|j| j.name == n).unwrap();

        let inh = by_name("inherits").escalation.unwrap();
        assert_eq!(inh.multiplier, 2.0);
        assert_eq!(inh.max_ban_time, Duration::from_secs(7200));
        assert_eq!(inh.window, Duration::from_secs(43200));

        assert!(by_name("disabled_escalation").escalation.is_none());

        let cust = by_name("custom").escalation.unwrap();
        assert_eq!(cust.multiplier, 3.0);
        assert_eq!(cust.max_ban_time, Duration::from_secs(3600));
        assert_eq!(cust.window, Duration::from_secs(43200));

        // Rejects multiplier < 1.0 or ban_time_max < ban_time
        assert!(Config::from_toml_str(
            "[global]\nban_time_multiplier = 0.5\n[jails.a]\nlog_path = \"/tmp/a\"\nfail_regex = ['from <HOST>$']\n"
        )
        .is_err());
        assert!(Config::from_toml_str(
            "[jails.a]\nlog_path = \"/tmp/a\"\nban_time = \"1h\"\nban_time_multiplier = 2.0\nban_time_max = \"10m\"\nfail_regex = ['from <HOST>$']\n"
        )
        .is_err());
    }
}
