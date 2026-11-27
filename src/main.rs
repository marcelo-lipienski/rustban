use std::collections::BTreeSet;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use rustban::config::{
    parse_duration_nonzero, validate_comment_safe, Config, LogFormat, LogSourceKind,
    DEFAULT_NFT_BIN, DEFAULT_TABLE_NAME,
};
use rustban::daemon::run_daemon_with_options;
use rustban::ip::{is_unbannable_special, IgnoreList, IpKey};
use rustban::matcher::{lint_fail_regexes, JailMatcher};
use rustban::nft::{format_prometheus_metrics, NftClient};

const DEFAULT_CONFIG_PATH: &str = "/etc/rustban/rustban.toml";

const VERSION: &str = match option_env!("RUSTBAN_VERSION") {
    Some(v) => {
        if v.is_empty() {
            env!("CARGO_PKG_VERSION")
        } else {
            v
        }
    }
    None => env!("CARGO_PKG_VERSION"),
};

#[derive(Debug, Parser)]
#[command(
    name = "rustban",
    version = VERSION,
    about = "Lightweight Fail2Ban replacement offloading ban expiration to Linux nftables timeout sets"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Run the rustban daemon watching configured log files and systemd units
    Run {
        /// Path to TOML configuration file
        #[arg(short, long, default_value = DEFAULT_CONFIG_PATH)]
        config: PathBuf,
        /// Log intended nftables rules and bans without modifying the kernel firewall
        #[arg(long)]
        dry_run: bool,
        /// Override daemon log output format (text or json)
        #[arg(long, value_enum)]
        log_format: Option<LogFormat>,
    },
    /// Show active bans, remaining kernel TTLs, and dropped packet counters from nftables
    Status {
        /// Optional config file to inherit table_name and nft_bin from
        #[arg(short, long)]
        config: Option<PathBuf>,
        /// Override nftables table name
        #[arg(long)]
        table: Option<String>,
        /// Override path to nft binary
        #[arg(long)]
        nft_bin: Option<PathBuf>,
        /// Emit machine-readable JSON output
        #[arg(long, conflicts_with = "prometheus")]
        json: bool,
        /// Emit Prometheus text exposition metrics (for node_exporter textfile collector)
        #[arg(long, conflicts_with = "json")]
        prometheus: bool,
    },
    /// Manually ban an IPv4 address or IPv6 /64 prefix directly in nftables
    Ban {
        /// IPv4 address, IPv6 address, or IPv6 /64 prefix
        ip: String,
        /// Ban duration (e.g. 10m, 1h, 24h)
        #[arg(short, long, default_value = "1h")]
        timeout: String,
        /// Reason stored in the nftables element comment
        #[arg(short, long, default_value = "manual")]
        reason: String,
        /// Optional config file to inherit table_name, nft_bin, and ignore_ips from
        #[arg(short, long)]
        config: Option<PathBuf>,
        /// Override nftables table name
        #[arg(long)]
        table: Option<String>,
        /// Override path to nft binary
        #[arg(long)]
        nft_bin: Option<PathBuf>,
        /// Allow banning even if the IP matches ignore_ips (kernel whitelist still applies)
        #[arg(long)]
        force: bool,
    },
    /// Manually remove an IPv4 address or IPv6 /64 prefix from nftables ban sets
    Unban {
        /// IPv4 address, IPv6 address, or IPv6 /64 prefix
        ip: String,
        /// Optional config file to inherit table_name and nft_bin from
        #[arg(short, long)]
        config: Option<PathBuf>,
        /// Override nftables table name
        #[arg(long)]
        table: Option<String>,
        /// Override path to nft binary
        #[arg(long)]
        nft_bin: Option<PathBuf>,
    },
    /// Flush all currently banned IPs while keeping the nftables table and rules intact
    Flush {
        /// Optional config file to inherit table_name and nft_bin from
        #[arg(short, long)]
        config: Option<PathBuf>,
        /// Override nftables table name
        #[arg(long)]
        table: Option<String>,
        /// Override path to nft binary
        #[arg(long)]
        nft_bin: Option<PathBuf>,
    },
    /// Remove the entire rustban nftables table from the kernel
    Teardown {
        /// Optional config file to inherit table_name and nft_bin from
        #[arg(short, long)]
        config: Option<PathBuf>,
        /// Override nftables table name
        #[arg(long)]
        table: Option<String>,
        /// Override path to nft binary
        #[arg(long)]
        nft_bin: Option<PathBuf>,
    },
    /// Validate configuration, regexes, CIDRs, and external binaries without starting the daemon
    Check {
        /// Path to TOML configuration file
        #[arg(short, long, default_value = DEFAULT_CONFIG_PATH)]
        config: PathBuf,
        /// Also validate disabled jails (enabled = false)
        #[arg(long)]
        include_disabled: bool,
        /// Fail with non-zero exit code if advisory regex safety or binary warnings are found
        #[arg(long)]
        strict: bool,
    },
    /// Offline regex and config tester against a log file or stdin ('-')
    Test {
        /// Path to TOML configuration file
        #[arg(short, long, default_value = DEFAULT_CONFIG_PATH)]
        config: PathBuf,
        /// Only test a specific jail name
        #[arg(short, long)]
        jail: Option<String>,
        /// Include disabled jails (enabled = false) when testing
        #[arg(long)]
        include_disabled: bool,
        /// Fail with non-zero exit code if advisory regex safety warnings are found
        #[arg(long)]
        strict: bool,
        /// Path to log file, or '-' to read from stdin
        log_file: String,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match execute(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn resolve_nft_client(
    config_path: Option<&Path>,
    table_override: Option<&str>,
    nft_bin_override: Option<&Path>,
) -> Result<(NftClient, Option<Config>), String> {
    let loaded_cfg = match config_path {
        Some(p) => Some(Config::from_file(p)?),
        None => None,
    };

    let table_name = table_override
        .map(String::from)
        .or_else(|| loaded_cfg.as_ref().map(|c| c.table_name.clone()))
        .unwrap_or_else(|| DEFAULT_TABLE_NAME.to_string());

    let nft_bin = nft_bin_override
        .map(PathBuf::from)
        .or_else(|| loaded_cfg.as_ref().map(|c| c.nft_bin.clone()))
        .unwrap_or_else(|| PathBuf::from(DEFAULT_NFT_BIN));

    let client = NftClient::new(nft_bin, table_name, false)?;
    Ok((client, loaded_cfg))
}

fn execute(cli: Cli) -> Result<(), String> {
    match cli.command {
        Commands::Run {
            config,
            dry_run,
            log_format,
        } => {
            let cfg = Config::from_file(&config)?;
            run_daemon_with_options(&config, &cfg, dry_run, log_format)
        }
        Commands::Status {
            config,
            table,
            nft_bin,
            json,
            prometheus,
        } => {
            let (client, _) =
                resolve_nft_client(config.as_deref(), table.as_deref(), nft_bin.as_deref())?;
            let status = client.status()?;
            if json {
                let out = serde_json::to_string_pretty(&status)
                    .map_err(|e| format!("failed to serialize status JSON: {e}"))?;
                println!("{out}");
                return Ok(());
            }
            if prometheus {
                print!("{}", format_prometheus_metrics(&status));
                return Ok(());
            }

            if !status.exists {
                println!(
                    "Table 'inet {}' does not exist in nftables (no active bans).",
                    status.table
                );
                return Ok(());
            }

            println!("Table: inet {}", status.table);
            println!(
                "Whitelisted CIDRs: {} IPv4, {} IPv6",
                status.whitelist_v4.len(),
                status.whitelist_v6.len()
            );
            println!("Active bans: {}", status.bans.len());
            if !status.bans.is_empty() {
                println!(
                    "{:<38} {:<16} {:<10} {:<10} {:>10} {:>12}",
                    "IP / PREFIX", "REASON", "EXPIRES", "TIMEOUT", "PACKETS", "BYTES"
                );
                for b in &status.bans {
                    let expires = b
                        .expires_secs
                        .map(format_secs)
                        .unwrap_or_else(|| "-".into());
                    let timeout = b
                        .timeout_secs
                        .map(format_secs)
                        .unwrap_or_else(|| "-".into());
                    let reason = b.comment.as_deref().unwrap_or("-");
                    println!(
                        "{:<38} {:<16} {:<10} {:<10} {:>10} {:>12}",
                        b.ip, reason, expires, timeout, b.packets, b.bytes
                    );
                }
            }
            Ok(())
        }
        Commands::Ban {
            ip,
            timeout,
            reason,
            config,
            table,
            nft_bin,
            force,
        } => {
            validate_comment_safe(&reason, "reason")?;
            let duration = parse_duration_nonzero(&timeout, "timeout")?;
            let key = IpKey::parse_user_input(&ip)?;
            if key.is_unbannable_special() {
                return Err(format!(
                    "refusing to ban special/non-routable address '{key}'"
                ));
            }
            let (client, cfg) =
                resolve_nft_client(config.as_deref(), table.as_deref(), nft_bin.as_deref())?;

            if !force {
                let ignores = match &cfg {
                    Some(c) => c.global_ignores.clone(),
                    None => IgnoreList::from_options(&[], true, true)?,
                };
                if ignores.contains_key(key) {
                    return Err(format!(
                        "refusing to ban whitelisted address '{key}' (pass --force to override userspace check)"
                    ));
                }
            }

            client.ban(key, duration, &reason)?;
            println!(
                "Banned {} in table 'inet {}' for {}s (reason: {})",
                key,
                client.table_name(),
                duration.as_secs(),
                reason
            );
            Ok(())
        }
        Commands::Unban {
            ip,
            config,
            table,
            nft_bin,
        } => {
            let key = IpKey::parse_user_input(&ip)?;
            let (client, _) =
                resolve_nft_client(config.as_deref(), table.as_deref(), nft_bin.as_deref())?;
            client.unban(key)?;
            println!("Unbanned {} from table 'inet {}'", key, client.table_name());
            Ok(())
        }
        Commands::Flush {
            config,
            table,
            nft_bin,
        } => {
            let (client, _) =
                resolve_nft_client(config.as_deref(), table.as_deref(), nft_bin.as_deref())?;
            client.flush()?;
            println!(
                "Flushed active bans in table 'inet {}'",
                client.table_name()
            );
            Ok(())
        }
        Commands::Teardown {
            config,
            table,
            nft_bin,
        } => {
            let (client, _) =
                resolve_nft_client(config.as_deref(), table.as_deref(), nft_bin.as_deref())?;
            client.teardown()?;
            println!("Removed table 'inet {}' from nftables", client.table_name());
            Ok(())
        }
        Commands::Check {
            config,
            include_disabled,
            strict,
        } => run_check(&config, include_disabled, strict),
        Commands::Test {
            config,
            jail,
            include_disabled,
            strict,
            log_file,
        } => run_test(
            &config,
            jail.as_deref(),
            include_disabled,
            strict,
            &log_file,
        ),
    }
}

fn run_check(config_path: &Path, include_disabled: bool, strict: bool) -> Result<(), String> {
    let cfg = Config::from_file_with_options(config_path, include_disabled)?;
    if cfg.jails.is_empty() {
        return Err("no enabled jails found in configuration".into());
    }

    let mut warnings: Vec<String> = Vec::new();
    let mut uses_journald = false;

    for jail in &cfg.jails {
        JailMatcher::compile(&jail.fail_regex, &jail.ignore_regex, cfg.max_line_bytes)?;
        if matches!(jail.source, LogSourceKind::Journald { .. }) {
            uses_journald = true;
        }
        for w in lint_fail_regexes(&jail.fail_regex) {
            warnings.push(format!(
                "jail '{}' pattern '{}': {}",
                jail.name, w.pattern, w.message
            ));
        }
    }

    if !cfg.nft_bin.exists() {
        warnings.push(format!(
            "configured nft_bin '{}' does not exist on this host",
            cfg.nft_bin.display()
        ));
    }
    if uses_journald && !cfg.journalctl_bin.exists() {
        warnings.push(format!(
            "configured journalctl_bin '{}' does not exist on this host",
            cfg.journalctl_bin.display()
        ));
    }

    for w in &warnings {
        eprintln!("warning: {w}");
    }

    println!(
        "Config OK: table=inet {} jails={} whitelisted_v4={} whitelisted_v6={} warnings={}",
        cfg.table_name,
        cfg.jails.len(),
        cfg.global_ignores.v4_cidrs().len(),
        cfg.global_ignores.v6_cidrs().len(),
        warnings.len()
    );

    if strict && !warnings.is_empty() {
        return Err(format!(
            "config check failed under --strict with {} warning(s)",
            warnings.len()
        ));
    }
    Ok(())
}

fn run_test(
    config_path: &Path,
    jail_filter: Option<&str>,
    include_disabled: bool,
    strict: bool,
    log_file: &str,
) -> Result<(), String> {
    let cfg = Config::from_file_with_options(config_path, include_disabled)?;
    let selected: Vec<_> = cfg
        .jails
        .iter()
        .filter(|j| jail_filter.map(|f| f == j.name).unwrap_or(true))
        .collect();

    if selected.is_empty() {
        return Err(match jail_filter {
            Some(name) => format!("jail '{name}' not found or not enabled in config"),
            None => "no enabled jails found in config".into(),
        });
    }

    let mut matchers = Vec::with_capacity(selected.len());
    let mut warnings: Vec<String> = Vec::new();
    for j in &selected {
        matchers.push(JailMatcher::compile(
            &j.fail_regex,
            &j.ignore_regex,
            cfg.max_line_bytes,
        )?);
        for w in lint_fail_regexes(&j.fail_regex) {
            warnings.push(format!(
                "jail '{}' pattern '{}': {}",
                j.name, w.pattern, w.message
            ));
        }
    }

    for w in &warnings {
        eprintln!("warning: {w}");
    }
    if strict && !warnings.is_empty() {
        return Err(format!(
            "regex safety check failed under --strict with {} warning(s)",
            warnings.len()
        ));
    }

    let reader: Box<dyn BufRead> = if log_file == "-" {
        Box::new(BufReader::new(io::stdin()))
    } else {
        let f = File::open(log_file)
            .map_err(|e| format!("failed to open log file '{log_file}': {e}"))?;
        Box::new(BufReader::new(f))
    };

    let mut total_lines = 0usize;
    let mut matched_counts = vec![0usize; selected.len()];
    let mut ignored_counts = vec![0usize; selected.len()];
    let mut unique_ips: Vec<BTreeSet<IpKey>> = vec![BTreeSet::new(); selected.len()];

    for line_res in reader.lines() {
        let line = line_res.map_err(|e| format!("error reading input: {e}"))?;
        total_lines += 1;
        for (idx, (jail, matcher)) in selected.iter().zip(&matchers).enumerate() {
            if let Some(raw_ip) = matcher.match_line(&line) {
                let key = IpKey::from_ip(raw_ip);
                if is_unbannable_special(raw_ip)
                    || key.is_unbannable_special()
                    || jail.ignore_ips.contains_ip(raw_ip)
                    || jail.ignore_ips.contains_key(key)
                {
                    ignored_counts[idx] += 1;
                } else {
                    matched_counts[idx] += 1;
                    unique_ips[idx].insert(key);
                }
            }
        }
    }

    println!("Config OK ({} lines scanned)", total_lines);
    for (idx, jail) in selected.iter().enumerate() {
        println!(
            "  jail={:<16} matches={:<6} ignored={:<6} unique_targets={}",
            jail.name,
            matched_counts[idx],
            ignored_counts[idx],
            unique_ips[idx].len()
        );
        for key in unique_ips[idx].iter().take(10) {
            println!("    -> {key}");
        }
        if unique_ips[idx].len() > 10 {
            println!("    -> ... (+{} more)", unique_ips[idx].len() - 10);
        }
    }
    Ok(())
}

fn format_secs(secs: u64) -> String {
    if secs >= 3600 {
        format!("{}h{}m{}s", secs / 3600, (secs % 3600) / 60, secs % 60)
    } else if secs >= 60 {
        format!("{}m{}s", secs / 60, secs % 60)
    } else {
        format!("{secs}s")
    }
}
