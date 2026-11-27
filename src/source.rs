use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};

#[derive(Debug)]
pub struct LogEvent {
    pub source_id: usize,
    pub line: String,
}

#[derive(Debug, Default)]
pub struct ChildRegistry {
    children: Mutex<Vec<u32>>,
}

impl ChildRegistry {
    pub fn register(&self, pid: u32) {
        if let Ok(mut guard) = self.children.lock() {
            guard.push(pid);
        }
    }

    pub fn unregister(&self, pid: u32) {
        if let Ok(mut guard) = self.children.lock() {
            guard.retain(|&p| p != pid);
        }
    }

    /// Terminate all spawned helper children (e.g. `journalctl -f`) on daemon shutdown.
    pub fn kill_all(&self) {
        if let Ok(guard) = self.children.lock() {
            for &pid in guard.iter() {
                let _ = Command::new("/bin/kill")
                    .args(["-TERM", &pid.to_string()])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
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
                        const MAX_PARTIAL: usize = 65_536;
                        if self.partial.len() < MAX_PARTIAL {
                            let take = (MAX_PARTIAL - self.partial.len()).min(slice.len());
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
    unit: String,
    tx: SyncSender<LogEvent>,
    shutdown: Arc<AtomicBool>,
    children: Arc<ChildRegistry>,
) -> JoinHandle<()> {
    thread::Builder::new()
        .name(format!("tail-journal-{source_id}"))
        .spawn(move || {
            run_journald_tailer(source_id, &journalctl_bin, &unit, &tx, &shutdown, &children);
        })
        .expect("failed to spawn journald tailer thread")
}

fn run_journald_tailer(
    source_id: usize,
    journalctl_bin: &Path,
    unit: &str,
    tx: &SyncSender<LogEvent>,
    shutdown: &Arc<AtomicBool>,
    children: &Arc<ChildRegistry>,
) {
    let mut backoff = Duration::from_secs(1);

    while !shutdown.load(Ordering::Relaxed) {
        eprintln!(
            "[rustban] tailing systemd unit '{unit}' via {}",
            journalctl_bin.display()
        );
        let child_res = Command::new(journalctl_bin)
            .args([
                "--follow",
                "--lines=0",
                "--output=cat",
                &format!("--unit={unit}"),
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn();

        match child_res {
            Ok(mut child) => {
                let pid = child.id();
                children.register(pid);
                backoff = Duration::from_secs(1);

                let stream_ok = stream_child_stdout(&mut child, source_id, tx, shutdown);
                let _ = child.kill();
                let status = child.wait();
                children.unregister(pid);

                if shutdown.load(Ordering::Relaxed) || !stream_ok {
                    break;
                }
                eprintln!(
                    "[rustban] warn: journalctl for unit '{unit}' exited ({status:?}); restarting in {}s",
                    backoff.as_secs()
                );
            }
            Err(e) => {
                eprintln!(
                    "[rustban] error spawning '{}' for unit '{unit}': {e}; retrying in {}s",
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

fn stream_child_stdout(
    child: &mut Child,
    source_id: usize,
    tx: &SyncSender<LogEvent>,
    shutdown: &AtomicBool,
) -> bool {
    let Some(stdout) = child.stdout.take() else {
        return true;
    };
    let mut reader = BufReader::new(stdout);
    let mut buf = Vec::new();
    loop {
        if shutdown.load(Ordering::Relaxed) {
            return false;
        }
        buf.clear();
        match reader.read_until(b'\n', &mut buf) {
            Ok(0) => return true,
            Ok(_) => {
                while buf.ends_with(b"\n") || buf.ends_with(b"\r") {
                    buf.pop();
                }
                if !buf.is_empty() {
                    let line = String::from_utf8_lossy(&buf).into_owned();
                    if tx.send(LogEvent { source_id, line }).is_err() {
                        return false;
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
}
