use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::json;

use crate::config::{Config, JailConfig, LogFormat, LogSourceKind};
use crate::ip::{discover_local_interface_ips, is_unbannable_special, IgnoreList, IpKey};
use crate::matcher::JailMatcher;
use crate::nft::NftClient;
use crate::source::{spawn_file_tailer, spawn_journald_tailer, ChildRegistry, LogEvent};
use crate::tracker::{EscalationTracker, FailureTracker};

struct CompiledJail {
    config: JailConfig,
    matcher: JailMatcher,
    tracker: FailureTracker,
    escalation: Option<EscalationTracker>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum SourceKey {
    File(PathBuf),
    Journald {
        units: Vec<String>,
        syslog_identifier: Option<String>,
    },
}

struct ActiveTailers {
    stop: Arc<AtomicBool>,
    children: Arc<ChildRegistry>,
    rx: mpsc::Receiver<LogEvent>,
    handles: Vec<JoinHandle<()>>,
}

impl ActiveTailers {
    fn shutdown(self) {
        self.stop.store(true, Ordering::Relaxed);
        self.children.kill_all();
        drop(self.rx);
        for h in self.handles {
            let _ = h.join();
        }
    }
}

pub fn run_daemon(config: &Config, dry_run: bool) -> Result<(), String> {
    run_daemon_inner(None, config, dry_run, None)
}

pub fn run_daemon_with_path(
    config_path: &Path,
    config: &Config,
    dry_run: bool,
) -> Result<(), String> {
    run_daemon_inner(Some(config_path), config, dry_run, None)
}

pub fn run_daemon_with_options(
    config_path: &Path,
    config: &Config,
    dry_run: bool,
    log_format_override: Option<LogFormat>,
) -> Result<(), String> {
    run_daemon_inner(Some(config_path), config, dry_run, log_format_override)
}

/// Format a `SystemTime` as UTC RFC 3339 (`YYYY-MM-DDTHH:MM:SSZ`) with zero external crates.
pub fn format_utc_rfc3339(now: SystemTime) -> String {
    let secs = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let hour = rem / 3600;
    let min = (rem % 3600) / 60;
    let sec = rem % 60;

    // Howard Hinnant's civil-from-days algorithm (days since 1970-01-01).
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}Z")
}

fn emit_json_log(level: &str, event: &str, mut fields: serde_json::Value) {
    if let Some(obj) = fields.as_object_mut() {
        obj.insert("ts".into(), json!(format_utc_rfc3339(SystemTime::now())));
        obj.insert("level".into(), json!(level));
        obj.insert("event".into(), json!(event));
    }
    eprintln!("{fields}");
}

struct CompiledRuntime {
    jails: Vec<CompiledJail>,
    sources: Vec<SourceKey>,
    source_subscribers: Vec<Vec<usize>>,
}

fn compile_jails_and_sources(config: &Config) -> Result<CompiledRuntime, String> {
    if config.jails.is_empty() {
        return Err("no enabled jails found in configuration".into());
    }

    let mut compiled_jails = Vec::with_capacity(config.jails.len());
    let mut source_map: HashMap<SourceKey, usize> = HashMap::new();
    let mut sources: Vec<SourceKey> = Vec::new();
    let mut source_subscribers: Vec<Vec<usize>> = Vec::new();

    for jail_cfg in &config.jails {
        let matcher = JailMatcher::compile(
            &jail_cfg.fail_regex,
            &jail_cfg.ignore_regex,
            config.max_line_bytes,
        )?;
        let tracker = FailureTracker::new(
            jail_cfg.find_time,
            jail_cfg.max_retries,
            jail_cfg.max_tracked_ips,
        );
        let escalation = jail_cfg.escalation.map(|esc| {
            EscalationTracker::new(
                jail_cfg.ban_time,
                esc.multiplier,
                esc.max_ban_time,
                esc.window,
                jail_cfg.max_tracked_ips,
            )
        });
        let jail_idx = compiled_jails.len();
        compiled_jails.push(CompiledJail {
            config: jail_cfg.clone(),
            matcher,
            tracker,
            escalation,
        });

        let key = match &jail_cfg.source {
            LogSourceKind::File(p) => SourceKey::File(p.clone()),
            LogSourceKind::Journald {
                units,
                syslog_identifier,
            } => SourceKey::Journald {
                units: units.clone(),
                syslog_identifier: syslog_identifier.clone(),
            },
        };

        let source_id = if let Some(&id) = source_map.get(&key) {
            id
        } else {
            let id = sources.len();
            source_map.insert(key.clone(), id);
            sources.push(key);
            source_subscribers.push(Vec::new());
            id
        };
        source_subscribers[source_id].push(jail_idx);
    }

    Ok(CompiledRuntime {
        jails: compiled_jails,
        sources,
        source_subscribers,
    })
}

fn spawn_tailers(config: &Config, sources: Vec<SourceKey>) -> ActiveTailers {
    let stop = Arc::new(AtomicBool::new(false));
    let children = Arc::new(ChildRegistry::default());
    let (tx, rx) = mpsc::sync_channel::<LogEvent>(4096);
    let mut handles = Vec::with_capacity(sources.len());

    for (source_id, source_key) in sources.into_iter().enumerate() {
        match source_key {
            SourceKey::File(path) => {
                handles.push(spawn_file_tailer(
                    source_id,
                    path,
                    true,
                    tx.clone(),
                    Arc::clone(&stop),
                ));
            }
            SourceKey::Journald {
                units,
                syslog_identifier,
            } => {
                handles.push(spawn_journald_tailer(
                    source_id,
                    config.journalctl_bin.clone(),
                    units,
                    syslog_identifier,
                    tx.clone(),
                    Arc::clone(&stop),
                    Arc::clone(&children),
                ));
            }
        }
    }
    drop(tx);

    ActiveTailers {
        stop,
        children,
        rx,
        handles,
    }
}

fn run_daemon_inner(
    config_path: Option<&Path>,
    initial_config: &Config,
    dry_run: bool,
    log_format_override: Option<LogFormat>,
) -> Result<(), String> {
    let CompiledRuntime {
        jails: mut compiled_jails,
        sources: initial_sources,
        mut source_subscribers,
    } = compile_jails_and_sources(initial_config)?;
    let mut active_cfg = initial_config.clone();
    let mut log_format = log_format_override.unwrap_or(active_cfg.log_format);

    let mut nft = NftClient::new(&active_cfg.nft_bin, &active_cfg.table_name, dry_run)?;
    nft.init_with_interfaces(&active_cfg.global_ignores, &active_cfg.ignore_interfaces)?;
    match log_format {
        LogFormat::Text => eprintln!(
            "[rustban] initialized nftables table 'inet {}' (dry_run={dry_run}, jails={}, ignore_interfaces={})",
            active_cfg.table_name,
            active_cfg.jails.len(),
            active_cfg.ignore_interfaces.len()
        ),
        LogFormat::Json => emit_json_log(
            "info",
            "init",
            json!({
                "table": active_cfg.table_name,
                "dry_run": dry_run,
                "jails": active_cfg.jails.len(),
                "ignore_interfaces": active_cfg.ignore_interfaces.len(),
            }),
        ),
    }

    let shutdown = Arc::new(AtomicBool::new(false));
    let reload_requested = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&shutdown))
        .map_err(|e| format!("failed to register SIGINT handler: {e}"))?;
    signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&shutdown))
        .map_err(|e| format!("failed to register SIGTERM handler: {e}"))?;
    signal_hook::flag::register(signal_hook::consts::SIGHUP, Arc::clone(&reload_requested))
        .map_err(|e| format!("failed to register SIGHUP handler: {e}"))?;

    let mut tailers = spawn_tailers(&active_cfg, initial_sources);

    let mut last_prune = Instant::now();
    let prune_interval = Duration::from_secs(60);

    // Only read /proc/net/* periodically when the user explicitly opted into ignore_self_refresh.
    let mut last_local_ips: Vec<IpAddr> =
        if active_cfg.ignore_self && active_cfg.ignore_self_refresh.is_some() {
            discover_local_interface_ips()
        } else {
            Vec::new()
        };
    let mut last_self_refresh = Instant::now();

    const MAX_EVENTS_PER_BATCH: usize = 4096;
    const MAX_BANS_PER_BATCH: usize = 256;
    let mut pending_bans: Vec<(IpKey, Duration, String)> = Vec::new();

    while !shutdown.load(Ordering::Relaxed) {
        if reload_requested.swap(false, Ordering::AcqRel) {
            if let Some(path) = config_path {
                match reload_configuration(path, &active_cfg, dry_run) {
                    Ok(ReloadOutcome {
                        config: new_cfg,
                        nft: new_nft,
                        runtime:
                            CompiledRuntime {
                                jails: new_jails,
                                sources: new_sources,
                                source_subscribers: new_subs,
                            },
                    }) => {
                        tailers.shutdown();
                        tailers = spawn_tailers(&new_cfg, new_sources);
                        active_cfg = new_cfg;
                        log_format = log_format_override.unwrap_or(active_cfg.log_format);
                        nft = new_nft;
                        compiled_jails = new_jails;
                        source_subscribers = new_subs;
                        last_local_ips =
                            if active_cfg.ignore_self && active_cfg.ignore_self_refresh.is_some() {
                                discover_local_interface_ips()
                            } else {
                                Vec::new()
                            };
                        last_self_refresh = Instant::now();
                        match log_format {
                            LogFormat::Text => eprintln!(
                                "[rustban] reloaded config from '{}' (jails={}, whitelisted_v4={}, whitelisted_v6={}, ignore_interfaces={})",
                                path.display(),
                                active_cfg.jails.len(),
                                active_cfg.global_ignores.v4_cidrs().len(),
                                active_cfg.global_ignores.v6_cidrs().len(),
                                active_cfg.ignore_interfaces.len()
                            ),
                            LogFormat::Json => emit_json_log(
                                "info",
                                "reload",
                                json!({
                                    "config_path": path.display().to_string(),
                                    "jails": active_cfg.jails.len(),
                                    "whitelisted_v4": active_cfg.global_ignores.v4_cidrs().len(),
                                    "whitelisted_v6": active_cfg.global_ignores.v6_cidrs().len(),
                                    "ignore_interfaces": active_cfg.ignore_interfaces.len(),
                                }),
                            ),
                        }
                    }
                    Err(e) => match log_format {
                        LogFormat::Text => eprintln!(
                            "[rustban] ERROR SIGHUP reload rejected (keeping previous config active): {e}"
                        ),
                        LogFormat::Json => {
                            emit_json_log("error", "reload_error", json!({ "error": e }))
                        }
                    },
                }
            } else {
                match log_format {
                    LogFormat::Text => eprintln!(
                        "[rustban] warn: SIGHUP received but daemon has no config file path"
                    ),
                    LogFormat::Json => emit_json_log(
                        "warn",
                        "reload_skipped",
                        json!({ "reason": "no config file path" }),
                    ),
                }
            }
        }

        match tailers.rx.recv_timeout(Duration::from_millis(250)) {
            Ok(first_event) => {
                let now = Instant::now();
                pending_bans.clear();
                process_log_event(
                    &first_event,
                    &source_subscribers,
                    &mut compiled_jails,
                    now,
                    log_format,
                    &mut pending_bans,
                );

                // Drain any already-queued events without blocking so attack bursts coalesce into
                // a single atomic `nft -f -` transaction while single bans flush immediately.
                let mut drained = 1usize;
                while drained < MAX_EVENTS_PER_BATCH && pending_bans.len() < MAX_BANS_PER_BATCH {
                    match tailers.rx.try_recv() {
                        Ok(ev) => {
                            drained += 1;
                            process_log_event(
                                &ev,
                                &source_subscribers,
                                &mut compiled_jails,
                                now,
                                log_format,
                                &mut pending_bans,
                            );
                        }
                        Err(_) => break,
                    }
                }

                if !pending_bans.is_empty() {
                    if let Err(e) = nft.ban_batch(&pending_bans) {
                        match log_format {
                            LogFormat::Text => eprintln!(
                                "[rustban] ERROR failed to apply ban batch ({} entries): {e}",
                                pending_bans.len()
                            ),
                            LogFormat::Json => emit_json_log(
                                "error",
                                "ban_batch_error",
                                json!({ "count": pending_bans.len(), "error": e }),
                            ),
                        }
                        if pending_bans.len() > 1 {
                            for (key, ban_time, jail_name) in &pending_bans {
                                if let Err(ie) = nft.ban(*key, *ban_time, jail_name) {
                                    match log_format {
                                        LogFormat::Text => eprintln!(
                                            "[rustban] ERROR failed to ban ip={key} jail={jail_name}: {ie}"
                                        ),
                                        LogFormat::Json => emit_json_log(
                                            "error",
                                            "ban_error",
                                            json!({
                                                "ip": key.to_string(),
                                                "jail": jail_name,
                                                "error": ie,
                                            }),
                                        ),
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }

        if active_cfg.ignore_self {
            if let Some(refresh_interval) = active_cfg.ignore_self_refresh {
                if last_self_refresh.elapsed() >= refresh_interval {
                    last_self_refresh = Instant::now();
                    let current_local_ips = discover_local_interface_ips();
                    if current_local_ips != last_local_ips {
                        match refresh_self_ignores(&mut active_cfg, &mut compiled_jails, &nft) {
                            Ok(()) => {
                                last_local_ips = current_local_ips;
                                match log_format {
                                    LogFormat::Text => eprintln!(
                                        "[rustban] refreshed ignore_self whitelist (whitelisted_v4={}, whitelisted_v6={})",
                                        active_cfg.global_ignores.v4_cidrs().len(),
                                        active_cfg.global_ignores.v6_cidrs().len()
                                    ),
                                    LogFormat::Json => emit_json_log(
                                        "info",
                                        "refresh_self",
                                        json!({
                                            "whitelisted_v4": active_cfg.global_ignores.v4_cidrs().len(),
                                            "whitelisted_v6": active_cfg.global_ignores.v6_cidrs().len(),
                                        }),
                                    ),
                                }
                            }
                            Err(e) => match log_format {
                                LogFormat::Text => eprintln!(
                                    "[rustban] ERROR failed to refresh ignore_self whitelist: {e}"
                                ),
                                LogFormat::Json => emit_json_log(
                                    "error",
                                    "refresh_self_error",
                                    json!({ "error": e }),
                                ),
                            },
                        }
                    }
                }
            }
        }

        if last_prune.elapsed() >= prune_interval {
            let now = Instant::now();
            for jail in &mut compiled_jails {
                jail.tracker.prune(now);
                if let Some(ref mut esc) = jail.escalation {
                    esc.prune(now);
                }
            }
            last_prune = now;
        }
    }

    match log_format {
        LogFormat::Text => eprintln!(
            "[rustban] shutting down (preserving active bans in kernel table 'inet {}')",
            active_cfg.table_name
        ),
        LogFormat::Json => emit_json_log(
            "info",
            "shutdown",
            json!({ "table": active_cfg.table_name, "preserved_bans": true }),
        ),
    }
    tailers.shutdown();
    Ok(())
}

struct ReloadOutcome {
    config: Config,
    nft: NftClient,
    runtime: CompiledRuntime,
}

fn reload_configuration(
    config_path: &Path,
    current_cfg: &Config,
    dry_run: bool,
) -> Result<ReloadOutcome, String> {
    let new_cfg = Config::from_file(config_path)?;
    if new_cfg.table_name != current_cfg.table_name {
        return Err(format!(
            "cannot change global.table_name on SIGHUP ('{}' -> '{}'); restart rustban instead",
            current_cfg.table_name, new_cfg.table_name
        ));
    }
    let runtime = compile_jails_and_sources(&new_cfg)?;
    let new_nft = NftClient::new(&new_cfg.nft_bin, &new_cfg.table_name, dry_run)?;
    new_nft.init_with_interfaces(&new_cfg.global_ignores, &new_cfg.ignore_interfaces)?;
    Ok(ReloadOutcome {
        config: new_cfg,
        nft: new_nft,
        runtime,
    })
}

fn refresh_self_ignores(
    active_cfg: &mut Config,
    compiled_jails: &mut [CompiledJail],
    nft: &NftClient,
) -> Result<(), String> {
    let new_global = IgnoreList::from_options(
        &active_cfg.raw_global_ignore_ips,
        active_cfg.include_default_ignores,
        true,
    )?;
    nft.refresh_whitelists(&new_global)?;
    for jail in compiled_jails.iter_mut() {
        let mut updated = new_global.clone();
        if !jail.config.raw_ignore_ips.is_empty() {
            let extra = IgnoreList::from_strings(&jail.config.raw_ignore_ips, false)?;
            updated.extend_from(&extra);
        }
        jail.config.ignore_ips = updated;
    }
    active_cfg.global_ignores = new_global;
    Ok(())
}

fn process_log_event(
    event: &LogEvent,
    source_subscribers: &[Vec<usize>],
    compiled_jails: &mut [CompiledJail],
    now: Instant,
    log_format: LogFormat,
    pending_bans: &mut Vec<(IpKey, Duration, String)>,
) {
    if let Some(jail_indices) = source_subscribers.get(event.source_id) {
        for &jail_idx in jail_indices {
            let jail = &mut compiled_jails[jail_idx];
            if let Some(raw_ip) = jail.matcher.match_line(&event.line) {
                let key = IpKey::from_ip(raw_ip);
                if is_unbannable_special(raw_ip)
                    || key.is_unbannable_special()
                    || jail.config.ignore_ips.contains_ip(raw_ip)
                    || jail.config.ignore_ips.contains_key(key)
                {
                    continue;
                }
                if jail.tracker.record_failure(key, now) {
                    let (ban_time, strike) = match jail.escalation.as_mut() {
                        Some(esc) => esc.record_ban(key, now),
                        None => (jail.config.ban_time, 1),
                    };
                    match log_format {
                        LogFormat::Text => {
                            if strike > 1 {
                                eprintln!(
                                    "[rustban] BAN jail={} ip={} timeout={}s strike={}",
                                    jail.config.name,
                                    key,
                                    ban_time.as_secs(),
                                    strike
                                );
                            } else {
                                eprintln!(
                                    "[rustban] BAN jail={} ip={} timeout={}s",
                                    jail.config.name,
                                    key,
                                    ban_time.as_secs()
                                );
                            }
                        }
                        LogFormat::Json => emit_json_log(
                            "info",
                            "ban",
                            json!({
                                "jail": jail.config.name,
                                "ip": key.to_string(),
                                "timeout_secs": ban_time.as_secs(),
                                "strike": strike,
                            }),
                        ),
                    }
                    pending_bans.push((key, ban_time, jail.config.name.clone()));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_utc_rfc3339_timestamps_accurately() {
        assert_eq!(format_utc_rfc3339(UNIX_EPOCH), "1970-01-01T00:00:00Z");
        // 2026-11-27T01:23:45Z
        let t = UNIX_EPOCH + Duration::from_secs(1_795_742_625);
        assert_eq!(format_utc_rfc3339(t), "2026-11-27T01:23:45Z");
    }
}
