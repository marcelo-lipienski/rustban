use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};

/// Cap incomplete/single log lines to 64 KiB so giant/binary lines cannot exhaust memory.
const MAX_LINE_BUF_BYTES: usize = 65_536;

#[derive(Debug)]
pub struct LogEvent {
    pub source_id: usize,
    pub line: String,
}

#[derive(Debug, Default)]
pub struct ChildRegistry {
    children: Mutex<Vec<Arc<Mutex<Option<Child>>>>>,
}

impl ChildRegistry {
    pub fn register(&self, child: Child) -> Arc<Mutex<Option<Child>>> {
        let handle = Arc::new(Mutex::new(Some(child)));
        if let Ok(mut guard) = self.children.lock() {
            guard.push(Arc::clone(&handle));
        }
        handle
    }

    pub fn unregister(&self, handle: &Arc<Mutex<Option<Child>>>) {
        if let Ok(mut guard) = self.children.lock() {
            guard.retain(|item| !Arc::ptr_eq(item, handle));
        }
    }

    /// Terminate all spawned helper children (e.g. `journalctl -f`) directly via `Child::kill()`
    /// without depending on an external `/bin/kill` binary.
    pub fn kill_all(&self) {
        let snapshot: Vec<Arc<Mutex<Option<Child>>>> = match self.children.lock() {
            Ok(guard) => guard.clone(),
            Err(_) => return,
        };
        for handle in snapshot {
            if let Ok(mut slot) = handle.lock() {
                if let Some(ref mut child) = *slot {
                    let _ = child.kill();
                }
            }
        }
    }
}

/// Spawn a file tailer thread supporting both inode rotation (`logrotate create`)
/// and in-place truncation (`logrotate copytruncate`).
pub fn spawn_file_tailer(
    source_id: usize,
    path: PathBuf,
    start_at_end: bool,
    tx: SyncSender<LogEvent>,
    shutdown: Arc<AtomicBool>,
) -> JoinHandle<()> {
    thread::Builder::new()
        .name(format!("tail-file-{source_id}"))
        .spawn(move || {
            run_file_tailer(source_id, &path, start_at_end, &tx, &shutdown);
        })
        .expect("failed to spawn file tailer thread")
}

struct OpenFile {
    file: File,
    dev: u64,
    ino: u64,
    offset: u64,
    partial: Vec<u8>,
}

impl OpenFile {
    fn open(path: &Path, seek_to_end: bool) -> std::io::Result<Self> {
        let mut file = File::open(path)?;
        let meta = file.metadata()?;
        let offset = if seek_to_end {
            file.seek(SeekFrom::End(0))?
        } else {
            file.seek(SeekFrom::Start(0))?
        };
        Ok(Self {
            file,
            dev: meta.dev(),
            ino: meta.ino(),
            offset,
            partial: Vec::new(),
        })
    }

    fn drain_lines(&mut self, source_id: usize, tx: &SyncSender<LogEvent>, shutdown: &AtomicBool) {
        let mut buf = vec![0u8; 65_536];
        loop {
            if shutdown.load(Ordering::Relaxed) {
                return;
            }
            match self.file.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    self.offset += n as u64;
                    let mut slice = &buf[..n];
                    while let Some(pos) = slice.iter().position(|&b| b == b'\n') {
                        self.partial.extend_from_slice(&slice[..pos]);
                        if self.partial.ends_with(b"\r") {
                            self.partial.pop();
                        }
                        let line = String::from_utf8_lossy(&self.partial).into_owned();
                        self.partial.clear();
                        if !line.is_empty() && tx.send(LogEvent { source_id, line }).is_err() {
                            return;
                        }
                        slice = &slice[pos + 1..];
                    }
                    if !slice.is_empty() {
                        // Cap incomplete partial lines to avoid unbounded growth on binary garbage.
                        if self.partial.len() < MAX_LINE_BUF_BYTES {
                            let take = (MAX_LINE_BUF_BYTES - self.partial.len()).min(slice.len());
                            self.partial.extend_from_slice(&slice[..take]);
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    eprintln!("[rustban] error reading log file: {e}");
                    break;
                }
            }
        }
    }
}

fn run_file_tailer(
    source_id: usize,
    path: &Path,
    start_at_end: bool,
    tx: &SyncSender<LogEvent>,
    shutdown: &Arc<AtomicBool>,
) {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    let (wtx, wrx) = mpsc::channel::<notify::Result<Event>>();
    let mut _watcher: Option<RecommendedWatcher> = notify::recommended_watcher(move |res| {
        let _ = wtx.send(res);
    })
    .ok();

    if let Some(ref mut watcher) = _watcher {
        if let Err(e) = watcher.watch(parent, RecursiveMode::NonRecursive) {
            eprintln!(
                "[rustban] warn: inotify watch on '{}' failed ({e}); falling back to polling",
                parent.display()
            );
        }
    }

    let mut current: Option<OpenFile> = match OpenFile::open(path, start_at_end) {
        Ok(f) => {
            eprintln!("[rustban] tailing file '{}'", path.display());
            Some(f)
        }
        Err(e) => {
            eprintln!("[rustban] waiting for log file '{}' ({e})", path.display());
            None
        }
    };

    // If starting from start of file (used in tests), drain immediately.
    if !start_at_end {
        if let Some(ref mut open) = current {
            open.drain_lines(source_id, tx, shutdown);
        }
    }

    while !shutdown.load(Ordering::Relaxed) {
        // Wake immediately on inotify events or every 250ms as fallback/shutdown poll.
        match wrx.recv_timeout(Duration::from_millis(250)) {
            Ok(_) => {
                // Coalesce burst of inotify events.
                while wrx.try_recv().is_ok() {}
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                thread::sleep(Duration::from_millis(250));
            }
        }

        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        if let Some(ref mut open) = current {
            open.drain_lines(source_id, tx, shutdown);
        }

        match fs::metadata(path) {
            Ok(meta) => match current {
                None => {
                    if let Ok(mut f) = OpenFile::open(path, false) {
                        eprintln!("[rustban] opened log file '{}'", path.display());
                        f.drain_lines(source_id, tx, shutdown);
                        current = Some(f);
                    }
                }
                Some(ref mut open) => {
                    if meta.dev() != open.dev || meta.ino() != open.ino {
                        // Inode rotated (e.g. logrotate rename + create)
                        open.drain_lines(source_id, tx, shutdown);
                        if let Ok(mut new_open) = OpenFile::open(path, false) {
                            eprintln!("[rustban] detected log rotation on '{}'", path.display());
                            new_open.drain_lines(source_id, tx, shutdown);
                            *open = new_open;
                        }
                    } else if meta.len() < open.offset {
                        // Truncated in place (e.g. logrotate copytruncate)
                        eprintln!("[rustban] detected log truncation on '{}'", path.display());
                        if open.file.seek(SeekFrom::Start(0)).is_ok() {
                            open.offset = 0;
                            open.partial.clear();
                            open.drain_lines(source_id, tx, shutdown);
                        }
                    }
                }
            },
            Err(_) => {
                // File temporarily absent during rotation; keep polling until recreated.
            }
        }
    }
}

/// Spawn a supervised `journalctl --follow` reader thread with automatic restart backoff.
pub fn spawn_journald_tailer(
    source_id: usize,
    journalctl_bin: PathBuf,
    units: Vec<String>,
    syslog_identifier: Option<String>,
    tx: SyncSender<LogEvent>,
    shutdown: Arc<AtomicBool>,
    children: Arc<ChildRegistry>,
) -> JoinHandle<()> {
    thread::Builder::new()
        .name(format!("tail-journal-{source_id}"))
        .spawn(move || {
            run_journald_tailer(
                source_id,
                &journalctl_bin,
                &units,
                syslog_identifier.as_deref(),
                &tx,
                &shutdown,
                &children,
            );
        })
        .expect("failed to spawn journald tailer thread")
}

pub fn build_journalctl_args(units: &[String], syslog_identifier: Option<&str>) -> Vec<String> {
    let mut args = vec![
        "--follow".to_string(),
        "--lines=0".to_string(),
        "--output=cat".to_string(),
    ];
    for u in units {
        args.push(format!("--unit={u}"));
    }
    if let Some(ident) = syslog_identifier {
        args.push(format!("--identifier={ident}"));
    }
    args
}

fn format_journal_desc(units: &[String], syslog_identifier: Option<&str>) -> String {
    match (units.is_empty(), syslog_identifier) {
        (false, Some(ident)) => format!("units=[{}] identifier={ident}", units.join(",")),
        (false, None) => format!("units=[{}]", units.join(",")),
        (true, Some(ident)) => format!("identifier={ident}"),
        (true, None) => "journald".to_string(),
    }
}

fn run_journald_tailer(
    source_id: usize,
    journalctl_bin: &Path,
    units: &[String],
    syslog_identifier: Option<&str>,
    tx: &SyncSender<LogEvent>,
    shutdown: &Arc<AtomicBool>,
    children: &Arc<ChildRegistry>,
) {
    let mut backoff = Duration::from_secs(1);
    let args = build_journalctl_args(units, syslog_identifier);
    let desc = format_journal_desc(units, syslog_identifier);

    while !shutdown.load(Ordering::Relaxed) {
        eprintln!(
            "[rustban] tailing systemd journal ({desc}) via {}",
            journalctl_bin.display()
        );
        let child_res = Command::new(journalctl_bin)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn();

        match child_res {
            Ok(mut child) => {
                let stdout = child.stdout.take();
                let handle = children.register(child);
                backoff = Duration::from_secs(1);

                let stream_ok = match stdout {
                    Some(out) => stream_reader_bounded(out, source_id, tx, shutdown),
                    None => true,
                };

                let status = {
                    let mut taken = handle.lock().ok().and_then(|mut slot| slot.take());
                    match taken.as_mut() {
                        Some(c) => {
                            let _ = c.kill();
                            Some(c.wait())
                        }
                        None => None,
                    }
                };
                children.unregister(&handle);

                if shutdown.load(Ordering::Relaxed) || !stream_ok {
                    break;
                }
                eprintln!(
                    "[rustban] warn: journalctl ({desc}) exited ({status:?}); restarting in {}s",
                    backoff.as_secs()
                );
            }
            Err(e) => {
                eprintln!(
                    "[rustban] error spawning '{}' ({desc}): {e}; retrying in {}s",
                    journalctl_bin.display(),
                    backoff.as_secs()
                );
            }
        }

        // Sleep in small increments so shutdown stays responsive.
        let steps = (backoff.as_millis() / 100).max(1);
        for _ in 0..steps {
            if shutdown.load(Ordering::Relaxed) {
                return;
            }
            thread::sleep(Duration::from_millis(100));
        }
        backoff = (backoff * 2).min(Duration::from_secs(10));
    }
}

fn stream_reader_bounded<R: Read>(
    mut reader: R,
    source_id: usize,
    tx: &SyncSender<LogEvent>,
    shutdown: &AtomicBool,
) -> bool {
    let mut chunk = vec![0u8; 65_536];
    let mut partial: Vec<u8> = Vec::new();
    let mut dropping_overflow = false;

    loop {
        if shutdown.load(Ordering::Relaxed) {
            return false;
        }
        match reader.read(&mut chunk) {
            Ok(0) => {
                if !partial.is_empty() {
                    if partial.ends_with(b"\r") {
                        partial.pop();
                    }
                    let line = String::from_utf8_lossy(&partial).into_owned();
                    partial.clear();
                    if !line.is_empty() && tx.send(LogEvent { source_id, line }).is_err() {
                        return false;
                    }
                }
                return true;
            }
            Ok(n) => {
                let mut slice = &chunk[..n];
                while let Some(pos) = slice.iter().position(|&b| b == b'\n') {
                    if !dropping_overflow && partial.len() < MAX_LINE_BUF_BYTES {
                        let take = (MAX_LINE_BUF_BYTES - partial.len()).min(pos);
                        partial.extend_from_slice(&slice[..take]);
                    }
                    if partial.ends_with(b"\r") {
                        partial.pop();
                    }
                    let line = String::from_utf8_lossy(&partial).into_owned();
                    partial.clear();
                    dropping_overflow = false;
                    if !line.is_empty() && tx.send(LogEvent { source_id, line }).is_err() {
                        return false;
                    }
                    slice = &slice[pos + 1..];
                }
                if !slice.is_empty() && !dropping_overflow {
                    if partial.len() < MAX_LINE_BUF_BYTES {
                        let take = (MAX_LINE_BUF_BYTES - partial.len()).min(slice.len());
                        partial.extend_from_slice(&slice[..take]);
                        if partial.len() >= MAX_LINE_BUF_BYTES {
                            dropping_overflow = true;
                        }
                    } else {
                        dropping_overflow = true;
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => {
                if !shutdown.load(Ordering::Relaxed) {
                    eprintln!("[rustban] error reading journalctl stdout: {e}");
                }
                return true;
            }
        }
    }
}

#[allow(dead_code)]
fn _assert_child_stdout_is_read(_: &ChildStdout) {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn file_tailer_handles_append_rotation_and_copytruncate() {
        let dir = tempdir().unwrap();
        let log_path = dir.path().join("auth.log");
        fs::write(&log_path, "old line before start\n").unwrap();

        let (tx, rx) = mpsc::sync_channel(64);
        let shutdown = Arc::new(AtomicBool::new(false));
        let handle = spawn_file_tailer(0, log_path.clone(), true, tx, Arc::clone(&shutdown));

        thread::sleep(Duration::from_millis(150));

        // 1. Append a normal line
        {
            let mut f = fs::OpenOptions::new().append(true).open(&log_path).unwrap();
            writeln!(f, "line-1").unwrap();
        }
        let ev1 = rx.recv_timeout(Duration::from_secs(3)).unwrap();
        assert_eq!(ev1.line, "line-1");

        // 2. Rotate via rename + recreate (new inode)
        let rotated = dir.path().join("auth.log.1");
        fs::rename(&log_path, &rotated).unwrap();
        fs::write(&log_path, "line-after-rotate\n").unwrap();
        let ev2 = rx.recv_timeout(Duration::from_secs(3)).unwrap();
        assert_eq!(ev2.line, "line-after-rotate");

        // 3. Truncate in place (copytruncate) with shorter content
        fs::write(&log_path, "short\n").unwrap();
        let ev3 = rx.recv_timeout(Duration::from_secs(3)).unwrap();
        assert_eq!(ev3.line, "short");

        shutdown.store(true, Ordering::Relaxed);
        handle.join().unwrap();
    }

    #[test]
    fn journalctl_args_and_bounded_stream_cap_giant_lines() {
        let args =
            build_journalctl_args(&["ssh.service".into(), "sshd.service".into()], Some("sshd"));
        assert_eq!(
            args,
            vec![
                "--follow",
                "--lines=0",
                "--output=cat",
                "--unit=ssh.service",
                "--unit=sshd.service",
                "--identifier=sshd",
            ]
        );

        // Stream a 256 KiB binary/text line without newline followed by a normal attack line
        let mut input = vec![b'A'; 256 * 1024];
        input.push(b'\n');
        input.extend_from_slice(b"Failed password for root from 203.0.113.88 port 22 ssh2\n");

        let (tx, rx) = mpsc::sync_channel(8);
        let shutdown = AtomicBool::new(false);
        let ok = stream_reader_bounded(&input[..], 7, &tx, &shutdown);
        assert!(ok);

        let ev1 = rx.recv().unwrap();
        assert_eq!(ev1.source_id, 7);
        assert_eq!(ev1.line.len(), MAX_LINE_BUF_BYTES);

        let ev2 = rx.recv().unwrap();
        assert_eq!(
            ev2.line,
            "Failed password for root from 203.0.113.88 port 22 ssh2"
        );
    }

    #[test]
    fn child_registry_kills_registered_child_without_external_kill_binary() {
        let registry = ChildRegistry::default();
        let child = Command::new("/bin/sh")
            .args(["-c", "sleep 30"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let handle = registry.register(child);
        registry.kill_all();
        let mut taken = handle.lock().unwrap().take().unwrap();
        let status = taken.wait().unwrap();
        assert!(!status.success());
        registry.unregister(&handle);
    }
}
