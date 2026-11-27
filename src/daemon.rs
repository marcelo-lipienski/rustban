use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::config::{Config, JailConfig, LogSourceKind};
use crate::ip::{is_unbannable_special, IpKey};
use crate::matcher::JailMatcher;
use crate::nft::NftClient;
use crate::source::{spawn_file_tailer, spawn_journald_tailer, ChildRegistry, LogEvent};
use crate::tracker::FailureTracker;

struct CompiledJail {
    config: JailConfig,
    matcher: JailMatcher,
    tracker: FailureTracker,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum SourceKey {
    File(PathBuf),
    Journald(String),
}

pub fn run_daemon(config: &Config, dry_run: bool) -> Result<(), String> {
    if config.jails.is_empty() {
        return Err("no enabled jails found in configuration".into());
    }

    let nft = NftClient::new(&config.nft_bin, &config.table_name, dry_run)?;
    nft.init(&config.global_ignores)?;
    eprintln!(
        "[rustban] initialized nftables table 'inet {}' (dry_run={dry_run}, jails={})",
        config.table_name,
        config.jails.len()
    );

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
        let jail_idx = compiled_jails.len();
        compiled_jails.push(CompiledJail {
            config: jail_cfg.clone(),
            matcher,
            tracker,
        });

        let key = match &jail_cfg.source {
            LogSourceKind::File(p) => SourceKey::File(p.clone()),
            LogSourceKind::Journald { unit } => SourceKey::Journald(unit.clone()),
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

    let shutdown = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&shutdown))
        .map_err(|e| format!("failed to register SIGINT handler: {e}"))?;
    signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&shutdown))
        .map_err(|e| format!("failed to register SIGTERM handler: {e}"))?;

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
                    Arc::clone(&shutdown),
                ));
            }
            SourceKey::Journald(unit) => {
                handles.push(spawn_journald_tailer(
                    source_id,
                    config.journalctl_bin.clone(),
                    unit,
                    tx.clone(),
                    Arc::clone(&shutdown),
                    Arc::clone(&children),
                ));
            }
        }
    }
    drop(tx);

    let mut last_prune = Instant::now();
    let prune_interval = Duration::from_secs(60);
    const MAX_EVENTS_PER_BATCH: usize = 4096;
    const MAX_BANS_PER_BATCH: usize = 256;
    let mut pending_bans: Vec<(IpKey, Duration, String)> = Vec::new();

    while !shutdown.load(Ordering::Relaxed) {
        match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(first_event) => {
                let now = Instant::now();
                pending_bans.clear();
                process_log_event(
                    &first_event,
                    &source_subscribers,
                    &mut compiled_jails,
                    now,
                    &mut pending_bans,
                );

                // Drain any already-queued events without blocking so attack bursts coalesce into
                // a single atomic `nft -f -` transaction while single bans flush immediately.
                let mut drained = 1usize;
                while drained < MAX_EVENTS_PER_BATCH && pending_bans.len() < MAX_BANS_PER_BATCH {
                    match rx.try_recv() {
                        Ok(ev) => {
                            drained += 1;
                            process_log_event(
                                &ev,
                                &source_subscribers,
                                &mut compiled_jails,
                                now,
                                &mut pending_bans,
                            );
                        }
                        Err(_) => break,
                    }
                }

                if !pending_bans.is_empty() {
                    if let Err(e) = nft.ban_batch(&pending_bans) {
                        eprintln!(
                            "[rustban] ERROR failed to apply ban batch ({} entries): {e}",
                            pending_bans.len()
                        );
                        if pending_bans.len() > 1 {
                            for (key, ban_time, jail_name) in &pending_bans {
                                if let Err(ie) = nft.ban(*key, *ban_time, jail_name) {
                                    eprintln!(
                                        "[rustban] ERROR failed to ban ip={key} jail={jail_name}: {ie}"
                                    );
                                }
                            }
                        }
                    }
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }

        if last_prune.elapsed() >= prune_interval {
            let now = Instant::now();
            for jail in &mut compiled_jails {
                jail.tracker.prune(now);
            }
            last_prune = now;
        }
    }

    eprintln!(
        "[rustban] shutting down (preserving active bans in kernel table 'inet {}')",
        config.table_name
    );
    shutdown.store(true, Ordering::Relaxed);
    children.kill_all();
    drop(rx);
    for h in handles {
        let _ = h.join();
    }
    Ok(())
}

fn process_log_event(
    event: &LogEvent,
    source_subscribers: &[Vec<usize>],
    compiled_jails: &mut [CompiledJail],
    now: Instant,
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
                    eprintln!(
                        "[rustban] BAN jail={} ip={} timeout={}s",
                        jail.config.name,
                        key,
                        jail.config.ban_time.as_secs()
                    );
                    pending_bans.push((key, jail.config.ban_time, jail.config.name.clone()));
                }
            }
        }
    }
}
