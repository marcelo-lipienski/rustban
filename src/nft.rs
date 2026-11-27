use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::{validate_comment_safe, validate_nft_ident};
use crate::ip::{IgnoreList, IpKey};

pub const SET_WHITELIST_V4: &str = "whitelist_v4";
pub const SET_WHITELIST_V6: &str = "whitelist_v6";
pub const SET_BANNED_V4: &str = "banned_v4";
pub const SET_BANNED_V6: &str = "banned_v6";
pub const CHAIN_PREROUTING: &str = "prerouting";

#[derive(Debug, Clone)]
pub struct NftClient {
    nft_bin: PathBuf,
    table_name: String,
    dry_run: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BanEntry {
    pub ip: String,
    pub family: String,
    pub timeout_secs: Option<u64>,
    pub expires_secs: Option<u64>,
    pub comment: Option<String>,
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableStatus {
    pub table: String,
    pub exists: bool,
    pub whitelist_v4: Vec<String>,
    pub whitelist_v6: Vec<String>,
    pub bans: Vec<BanEntry>,
}

impl NftClient {
    pub fn new(
        nft_bin: impl Into<PathBuf>,
        table_name: impl Into<String>,
        dry_run: bool,
    ) -> Result<Self, String> {
        let table_name = table_name.into();
        validate_nft_ident(&table_name, "table_name")?;
        Ok(Self {
            nft_bin: nft_bin.into(),
            table_name,
            dry_run,
        })
    }

    pub fn table_name(&self) -> &str {
        &self.table_name
    }

    pub fn nft_bin(&self) -> &Path {
        &self.nft_bin
    }

    /// Build the idempotent initialization script.
    /// Preserves existing `banned_v4` / `banned_v6` elements and remaining timeouts across restarts,
    /// while cleanly refreshing `whitelist_v4` / `whitelist_v6` and `prerouting` rule order.
    pub fn build_init_script(&self, ignores: &IgnoreList) -> String {
        let t = &self.table_name;
        let mut s = String::with_capacity(1024);
        s.push_str(&format!("add table inet {t}\n"));
        s.push_str(&format!(
            "add set inet {t} {SET_WHITELIST_V4} {{ type ipv4_addr; flags interval; auto-merge; }}\n"
        ));
        s.push_str(&format!(
            "add set inet {t} {SET_WHITELIST_V6} {{ type ipv6_addr; flags interval; auto-merge; }}\n"
        ));
        s.push_str(&format!(
            "add set inet {t} {SET_BANNED_V4} {{ type ipv4_addr; flags timeout; counter; }}\n"
        ));
        s.push_str(&format!(
            "add set inet {t} {SET_BANNED_V6} {{ type ipv6_addr; flags timeout; counter; }}\n"
        ));
        s.push_str(&format!(
            "add chain inet {t} {CHAIN_PREROUTING} {{ type filter hook prerouting priority raw; policy accept; }}\n"
        ));
        s.push_str(&format!("flush chain inet {t} {CHAIN_PREROUTING}\n"));
        s.push_str(&format!("flush set inet {t} {SET_WHITELIST_V4}\n"));
        s.push_str(&format!("flush set inet {t} {SET_WHITELIST_V6}\n"));

        if !ignores.v4_cidrs().is_empty() {
            let elems: Vec<String> = ignores.v4_cidrs().iter().map(|c| c.to_string()).collect();
            s.push_str(&format!(
                "add element inet {t} {SET_WHITELIST_V4} {{ {} }}\n",
                elems.join(", ")
            ));
        }
        if !ignores.v6_cidrs().is_empty() {
            let elems: Vec<String> = ignores.v6_cidrs().iter().map(|c| c.to_string()).collect();
            s.push_str(&format!(
                "add element inet {t} {SET_WHITELIST_V6} {{ {} }}\n",
                elems.join(", ")
            ));
        }

        s.push_str(&format!(
            "add rule inet {t} {CHAIN_PREROUTING} ip saddr @{SET_WHITELIST_V4} return\n"
        ));
        s.push_str(&format!(
            "add rule inet {t} {CHAIN_PREROUTING} ip6 saddr @{SET_WHITELIST_V6} return\n"
        ));
        s.push_str(&format!(
            "add rule inet {t} {CHAIN_PREROUTING} ip saddr @{SET_BANNED_V4} drop\n"
        ));
        s.push_str(&format!(
            "add rule inet {t} {CHAIN_PREROUTING} ip6 saddr & ffff:ffff:ffff:ffff:: @{SET_BANNED_V6} drop\n"
        ));
        s
    }

    /// Build an atomic ban/refresh script compatible with nftables >= 0.9 (no `destroy` needed).
    /// `add` (idempotent) + `delete` + `add` inside one atomic `nft -f -` transaction atomically
    /// inserts a new ban OR refreshes the timeout/comment of an existing ban with zero leak gap.
    pub fn build_ban_script(
        &self,
        key: IpKey,
        timeout: Duration,
        comment: &str,
    ) -> Result<String, String> {
        self.build_ban_batch_script(&[(key, timeout, comment.to_string())])
    }

    /// Build a single atomic `nft -f -` script banning/refreshing multiple IPs in one kernel
    /// netlink transaction. Deduplicates repeated keys within the batch (keeping the latest entry)
    /// so every `add`/`delete` set-element list is valid under nftables >= 0.9.
    pub fn build_ban_batch_script(
        &self,
        bans: &[(IpKey, Duration, String)],
    ) -> Result<String, String> {
        if bans.is_empty() {
            return Ok(String::new());
        }

        // Preserve insertion order while deduplicating repeated keys (last entry wins).
        let mut order: Vec<IpKey> = Vec::with_capacity(bans.len());
        let mut dedup: HashMap<IpKey, (Duration, &str)> = HashMap::with_capacity(bans.len());
        for (key, timeout, comment) in bans {
            if key.is_unbannable_special() {
                return Err(format!(
                    "refusing to ban special/non-routable address '{key}'"
                ));
            }
            validate_comment_safe(comment, "ban comment")?;
            if !dedup.contains_key(key) {
                order.push(*key);
            }
            dedup.insert(*key, (*timeout, comment.as_str()));
        }

        let t = &self.table_name;
        let mut v4_prime = Vec::new();
        let mut v4_del = Vec::new();
        let mut v4_final = Vec::new();
        let mut v6_prime = Vec::new();
        let mut v6_del = Vec::new();
        let mut v6_final = Vec::new();

        for key in order {
            let (timeout, comment) = dedup[&key];
            let secs = timeout.as_secs().max(1);
            let elem = key.nft_element();
            if key.is_v4() {
                v4_prime.push(format!("{elem} timeout 1s"));
                v4_del.push(elem.clone());
                v4_final.push(format!("{elem} timeout {secs}s comment \"{comment}\""));
            } else {
                v6_prime.push(format!("{elem} timeout 1s"));
                v6_del.push(elem.clone());
                v6_final.push(format!("{elem} timeout {secs}s comment \"{comment}\""));
            }
        }

        let mut script = String::with_capacity(bans.len() * 96);
        if !v4_final.is_empty() {
            script.push_str(&format!(
                "add element inet {t} {SET_BANNED_V4} {{ {} }}\n\
                 delete element inet {t} {SET_BANNED_V4} {{ {} }}\n\
                 add element inet {t} {SET_BANNED_V4} {{ {} }}\n",
                v4_prime.join(", "),
                v4_del.join(", "),
                v4_final.join(", "),
            ));
        }
        if !v6_final.is_empty() {
            script.push_str(&format!(
                "add element inet {t} {SET_BANNED_V6} {{ {} }}\n\
                 delete element inet {t} {SET_BANNED_V6} {{ {} }}\n\
                 add element inet {t} {SET_BANNED_V6} {{ {} }}\n",
                v6_prime.join(", "),
                v6_del.join(", "),
                v6_final.join(", "),
            ));
        }
        Ok(script)
    }

    /// Build an idempotent unban script compatible with nftables >= 0.9.
    pub fn build_unban_script(&self, key: IpKey) -> String {
        let t = &self.table_name;
        let set = if key.is_v4() {
            SET_BANNED_V4
        } else {
            SET_BANNED_V6
        };
        let elem = key.nft_element();
        format!(
            "add element inet {t} {set} {{ {elem} timeout 1s }}\n\
             delete element inet {t} {set} {{ {elem} }}\n"
        )
    }

    pub fn build_flush_script(&self) -> String {
        let t = &self.table_name;
        format!(
            "flush set inet {t} {SET_BANNED_V4}\n\
             flush set inet {t} {SET_BANNED_V6}\n"
        )
    }

    pub fn build_teardown_script(&self) -> String {
        let t = &self.table_name;
        format!(
            "add table inet {t}\n\
             delete table inet {t}\n"
        )
    }

    pub fn init(&self, ignores: &IgnoreList) -> Result<(), String> {
        let script = self.build_init_script(ignores);
        self.apply_script(&script)
    }

    pub fn ban(&self, key: IpKey, timeout: Duration, comment: &str) -> Result<(), String> {
        let script = self.build_ban_script(key, timeout, comment)?;
        self.apply_script(&script)
    }

    pub fn ban_batch(&self, bans: &[(IpKey, Duration, String)]) -> Result<(), String> {
        if bans.is_empty() {
            return Ok(());
        }
        let script = self.build_ban_batch_script(bans)?;
        self.apply_script(&script)
    }

    pub fn unban(&self, key: IpKey) -> Result<(), String> {
        let script = self.build_unban_script(key);
        self.apply_script(&script)
    }

    pub fn flush(&self) -> Result<(), String> {
        let script = self.build_flush_script();
        self.apply_script(&script)
    }

    pub fn teardown(&self) -> Result<(), String> {
        let script = self.build_teardown_script();
        self.apply_script(&script)
    }

    pub fn apply_script(&self, script: &str) -> Result<(), String> {
        if self.dry_run {
            eprintln!("[dry-run] nft -f - <<EOF\n{script}EOF");
            return Ok(());
        }

        let mut child = Command::new(&self.nft_bin)
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("failed to spawn '{}': {e}", self.nft_bin.display()))?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(script.as_bytes())
                .map_err(|e| format!("failed writing nft script to stdin: {e}"))?;
        }

        let output = child
            .wait_with_output()
            .map_err(|e| format!("failed waiting on nft: {e}"))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!(
                "nft exited with {}: {}",
                output.status,
                stderr.trim()
            ));
        }
        Ok(())
    }

    pub fn status(&self) -> Result<TableStatus, String> {
        let output = Command::new(&self.nft_bin)
            .args(["-j", "list", "table", "inet", &self.table_name])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .map_err(|e| format!("failed to run '{}': {e}", self.nft_bin.display()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("No such file or directory") || stderr.contains("does not exist") {
                return Ok(TableStatus {
                    table: self.table_name.clone(),
                    exists: false,
                    whitelist_v4: Vec::new(),
                    whitelist_v6: Vec::new(),
                    bans: Vec::new(),
                });
            }
            return Err(format!(
                "nft -j list table inet {} failed ({}): {}",
                self.table_name,
                output.status,
                stderr.trim()
            ));
        }

        let json_str = String::from_utf8_lossy(&output.stdout);
        parse_table_status(&self.table_name, &json_str)
    }
}

pub fn parse_table_status(table_name: &str, json_str: &str) -> Result<TableStatus, String> {
    let root: Value = serde_json::from_str(json_str)
        .map_err(|e| format!("failed to parse nft JSON output: {e}"))?;
    let items = root
        .get("nftables")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "unexpected nft JSON: missing 'nftables' array".to_string())?;

    let mut whitelist_v4 = Vec::new();
    let mut whitelist_v6 = Vec::new();
    let mut bans = Vec::new();

    for item in items {
        let Some(set_obj) = item.get("set") else {
            continue;
        };
        let Some(name) = set_obj.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(elems) = set_obj.get("elem").and_then(|v| v.as_array()) else {
            continue;
        };

        match name {
            SET_WHITELIST_V4 => {
                for e in elems {
                    if let Some(s) = format_whitelist_elem(e) {
                        whitelist_v4.push(s);
                    }
                }
            }
            SET_WHITELIST_V6 => {
                for e in elems {
                    if let Some(s) = format_whitelist_elem(e) {
                        whitelist_v6.push(s);
                    }
                }
            }
            SET_BANNED_V4 => {
                for e in elems {
                    if let Some(entry) = parse_ban_elem(e, "ipv4") {
                        bans.push(entry);
                    }
                }
            }
            SET_BANNED_V6 => {
                for e in elems {
                    if let Some(mut entry) = parse_ban_elem(e, "ipv6") {
                        if !entry.ip.contains('/') {
                            entry.ip.push_str("/64");
                        }
                        bans.push(entry);
                    }
                }
            }
            _ => {}
        }
    }

    bans.sort_by(|a, b| a.ip.cmp(&b.ip));

    Ok(TableStatus {
        table: table_name.to_string(),
        exists: true,
        whitelist_v4,
        whitelist_v6,
        bans,
    })
}

fn format_whitelist_elem(v: &Value) -> Option<String> {
    if let Some(s) = v.as_str() {
        return Some(s.to_string());
    }
    if let Some(prefix) = v.get("prefix") {
        let addr = prefix.get("addr")?.as_str()?;
        let len = prefix.get("len")?.as_u64()?;
        return Some(format!("{addr}/{len}"));
    }
    if let Some(range) = v.get("range").and_then(|r| r.as_array()) {
        if range.len() == 2 {
            return Some(format!(
                "{}-{}",
                range[0].as_str().unwrap_or("?"),
                range[1].as_str().unwrap_or("?")
            ));
        }
    }
    None
}

fn parse_ban_elem(v: &Value, family: &str) -> Option<BanEntry> {
    if let Some(ip) = v.as_str() {
        return Some(BanEntry {
            ip: ip.to_string(),
            family: family.to_string(),
            timeout_secs: None,
            expires_secs: None,
            comment: None,
            packets: 0,
            bytes: 0,
        });
    }

    let elem = v.get("elem")?;
    let val = elem.get("val")?;
    let ip = if let Some(s) = val.as_str() {
        s.to_string()
    } else {
        let prefix = val.get("prefix")?;
        format!(
            "{}/{}",
            prefix.get("addr")?.as_str()?,
            prefix.get("len")?.as_u64()?
        )
    };

    let timeout_secs = json_number_as_u64(elem.get("timeout"));
    let expires_secs = json_number_as_u64(elem.get("expires"));
    let comment = elem
        .get("comment")
        .and_then(|c| c.as_str())
        .map(|s| s.to_string());

    let (packets, bytes) = if let Some(counter) = elem.get("counter") {
        (
            json_number_as_u64(counter.get("packets")).unwrap_or(0),
            json_number_as_u64(counter.get("bytes")).unwrap_or(0),
        )
    } else {
        (0, 0)
    };

    Some(BanEntry {
        ip,
        family: family.to_string(),
        timeout_secs,
        expires_secs,
        comment,
        packets,
        bytes,
    })
}

fn json_number_as_u64(v: Option<&Value>) -> Option<u64> {
    let v = v?;
    if let Some(u) = v.as_u64() {
        Some(u)
    } else if let Some(f) = v.as_f64() {
        if f >= 0.0 {
            Some(f.round() as u64)
        } else {
            None
        }
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nft_json_status_with_counters_and_comments() {
        let json = r#"{
          "nftables": [
            {"metainfo": {"version": "1.0.6", "json_schema_version": 1}},
            {"table": {"family": "inet", "name": "rustban", "handle": 1}},
            {"set": {
              "family": "inet", "name": "whitelist_v4", "table": "rustban",
              "type": "ipv4_addr", "flags": ["interval"],
              "elem": [{"prefix": {"addr": "127.0.0.0", "len": 8}}]
            }},
            {"set": {
              "family": "inet", "name": "banned_v4", "table": "rustban",
              "type": "ipv4_addr", "flags": ["timeout"],
              "elem": [{
                "elem": {
                  "val": "203.0.113.42",
                  "timeout": 3600,
                  "expires": 3512,
                  "comment": "sshd",
                  "counter": {"packets": 17, "bytes": 1020}
                }
              }]
            }},
            {"set": {
              "family": "inet", "name": "banned_v6", "table": "rustban",
              "type": "ipv6_addr", "flags": ["timeout"],
              "elem": [{
                "elem": {
                  "val": "2001:db8:abcd:1234::",
                  "timeout": 3600,
                  "expires": 3400.4,
                  "comment": "nginx",
                  "counter": {"packets": 4, "bytes": 320}
                }
              }]
            }}
          ]
        }"#;

        let status = parse_table_status("rustban", json).unwrap();
        assert!(status.exists);
        assert_eq!(status.whitelist_v4, vec!["127.0.0.0/8"]);
        assert_eq!(status.bans.len(), 2);
        assert_eq!(status.bans[0].ip, "2001:db8:abcd:1234::/64");
        assert_eq!(status.bans[0].expires_secs, Some(3400));
        assert_eq!(status.bans[0].packets, 4);
        assert_eq!(status.bans[1].ip, "203.0.113.42");
        assert_eq!(status.bans[1].comment.as_deref(), Some("sshd"));
        assert_eq!(status.bans[1].packets, 17);
    }

    #[test]
    fn builds_init_and_ban_scripts_cleanly() {
        let client = NftClient::new("/usr/sbin/nft", "rustban", true).unwrap();
        let ignores = IgnoreList::from_strings(&["10.0.0.0/8".into()], true).unwrap();
        let init = client.build_init_script(&ignores);
        assert!(init.contains("add table inet rustban"));
        assert!(init.contains("ip saddr @whitelist_v4 return"));
        assert!(init.contains("ip6 saddr & ffff:ffff:ffff:ffff:: @banned_v6 drop"));
        assert!(!init.contains("flush set inet rustban banned_v4"));

        let ban = client
            .build_ban_script(
                IpKey::V4("203.0.113.9".parse().unwrap()),
                Duration::from_secs(600),
                "sshd",
            )
            .unwrap();
        assert!(ban.contains("timeout 600s comment \"sshd\""));

        let batch = client
            .build_ban_batch_script(&[
                (
                    IpKey::V4("203.0.113.9".parse().unwrap()),
                    Duration::from_secs(60),
                    "sshd".into(),
                ),
                (
                    IpKey::V4("203.0.113.9".parse().unwrap()),
                    Duration::from_secs(300),
                    "nginx".into(),
                ),
                (
                    IpKey::V4("203.0.113.10".parse().unwrap()),
                    Duration::from_secs(300),
                    "sshd".into(),
                ),
                (
                    IpKey::from_ip("2001:db8:abcd:1234::5".parse().unwrap()),
                    Duration::from_secs(600),
                    "sshd".into(),
                ),
            ])
            .unwrap();
        // Deduplicated: 203.0.113.9 appears once in each of the 3 IPv4 lines with latest timeout/comment
        assert_eq!(batch.matches("203.0.113.9").count(), 3);
        assert!(batch.contains("203.0.113.9 timeout 300s comment \"nginx\""));
        assert!(batch.contains("203.0.113.10 timeout 300s comment \"sshd\""));
        assert!(batch.contains("add element inet rustban banned_v6 { 2001:db8:abcd:1234:: timeout 600s comment \"sshd\" }"));
    }
}
