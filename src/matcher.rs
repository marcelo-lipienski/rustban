use std::net::IpAddr;
use std::str::FromStr;

use regex::Regex;

/// Linear-time IPv4 or IPv6 capture token replacing `<HOST>` in jail patterns.
/// - IPv4 matches dotted quads without consuming trailing `:port`.
/// - IPv6 matches standard and IPv4-mapped IPv6 addresses.
pub const HOST_PATTERN: &str = r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3}|(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?:\.(?:\d{1,3}\.){3}\d{1,3})?)";

#[derive(Debug, Clone)]
pub struct JailMatcher {
    fail_regexes: Vec<Regex>,
    ignore_regexes: Vec<Regex>,
    max_line_bytes: usize,
}

impl JailMatcher {
    pub fn compile(
        fail_patterns: &[String],
        ignore_patterns: &[String],
        max_line_bytes: usize,
    ) -> Result<Self, String> {
        let mut fail_regexes = Vec::with_capacity(fail_patterns.len());
        for raw in fail_patterns {
            let expanded = expand_host_token(raw);
            let re =
                Regex::new(&expanded).map_err(|e| format!("invalid fail_regex '{raw}': {e}"))?;
            if re.capture_names().flatten().all(|n| n != "ip") {
                return Err(format!(
                    "fail_regex '{raw}' must include '<HOST>' or a named '(?P<ip>...)' capture group"
                ));
            }
            fail_regexes.push(re);
        }

        let mut ignore_regexes = Vec::with_capacity(ignore_patterns.len());
        for raw in ignore_patterns {
            let expanded = expand_host_token(raw);
            let re =
                Regex::new(&expanded).map_err(|e| format!("invalid ignore_regex '{raw}': {e}"))?;
            ignore_regexes.push(re);
        }

        Ok(Self {
            fail_regexes,
            ignore_regexes,
            max_line_bytes,
        })
    }

    /// Inspect a single log line and return the extracted `IpAddr` if a fail pattern matches
    /// (and no ignore pattern matches).
    pub fn match_line(&self, line: &str) -> Option<IpAddr> {
        let capped = truncate_utf8(line, self.max_line_bytes);
        if self.ignore_regexes.iter().any(|re| re.is_match(capped)) {
            return None;
        }
        for re in &self.fail_regexes {
            if let Some(caps) = re.captures(capped) {
                if let Some(m) = caps.name("ip") {
                    let raw = m.as_str().trim_start_matches('[').trim_end_matches(']');
                    if let Ok(ip) = IpAddr::from_str(raw) {
                        return Some(ip);
                    }
                }
            }
        }
        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegexWarning {
    pub pattern: String,
    pub message: String,
}

/// Inspect a `fail_regex` pattern for common log-injection / spoofing footguns:
/// - Unanchored end (`$`) when `<HOST>` is not anchored at start-of-line (`^<HOST>`).
/// - Non-greedy wildcard (`.*?` or `.+?`) preceding `<HOST>` / `(?P<ip>...)`, which can let
///   attacker-controlled usernames or URIs inject a spoofed victim IP earlier on the line.
pub fn lint_fail_regex(pattern: &str) -> Vec<RegexWarning> {
    let mut warnings = Vec::new();
    let trimmed = pattern.trim();

    let host_pos = trimmed.find("<HOST>").or_else(|| trimmed.find("(?P<ip>"));

    let anchored_at_start_host = trimmed.starts_with("^<HOST>")
        || trimmed.starts_with("^(?P<ip>")
        || trimmed.starts_with("^\\[?<HOST>");

    if !anchored_at_start_host && !trimmed.ends_with('$') {
        warnings.push(RegexWarning {
            pattern: pattern.to_string(),
            message: "fail_regex does not end with '$' — consider anchoring to end-of-line to prevent trailing log-injection spoofing".to_string(),
        });
    }

    if let Some(pos) = host_pos {
        let prefix = &trimmed[..pos];
        if prefix.contains(".*?") || prefix.contains(".+?") {
            warnings.push(RegexWarning {
                pattern: pattern.to_string(),
                message: "non-greedy wildcard (.*? or .+?) before <HOST> may match a spoofed IP inside attacker-controlled text (use greedy .* or .+ with an end anchor instead)".to_string(),
            });
        }
    }

    warnings
}

pub fn lint_fail_regexes(patterns: &[String]) -> Vec<RegexWarning> {
    let mut out = Vec::new();
    for p in patterns {
        out.extend(lint_fail_regex(p));
    }
    out
}

pub fn expand_host_token(pattern: &str) -> String {
    pattern.replace("<HOST>", HOST_PATTERN)
}

fn truncate_utf8(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_ipv4_ipv6_and_ignores_port() {
        let m = JailMatcher::compile(
            &[
                r"Failed password for (?:invalid user )?\S+ from <HOST> port \d+".into(),
                r#"client: \[?<HOST>\]?(?::\d+)?"#.into(),
            ],
            &[r"Failed password for admin from".into()],
            4096,
        )
        .unwrap();

        assert_eq!(
            m.match_line("Failed password for root from 203.0.113.55 port 44122 ssh2"),
            Some("203.0.113.55".parse().unwrap())
        );
        assert_eq!(
            m.match_line(
                "Failed password for invalid user bob from 2001:db8:abcd:1::9 port 51234 ssh2"
            ),
            Some("2001:db8:abcd:1::9".parse().unwrap())
        );
        assert_eq!(
            m.match_line("error client: 198.51.100.12:8080 denied"),
            Some("198.51.100.12".parse().unwrap())
        );
        assert_eq!(
            m.match_line("error client: [2001:db8:1:2::99]:443 denied"),
            Some("2001:db8:1:2::99".parse().unwrap())
        );
        // Ignored by ignore_regex
        assert_eq!(
            m.match_line("Failed password for admin from 203.0.113.55 port 44122 ssh2"),
            None
        );
    }

    #[test]
    fn rejects_regex_without_host_or_ip_capture() {
        let err = JailMatcher::compile(&[r"Failed password for root".into()], &[], 4096);
        assert!(err.is_err());
    }

    #[test]
    fn lints_unanchored_and_non_greedy_fail_regexes() {
        // Anchored greedy sshd pattern -> clean
        assert!(lint_fail_regex(r"Failed password for .+ from <HOST> port \d+ ssh2$").is_empty());
        // Start-anchored <HOST> pattern (nginx access log) -> clean
        assert!(lint_fail_regex(r#"^<HOST> \S+ \S+ "GET /\.env" 404 "#).is_empty());

        // Missing end anchor -> 1 warning
        let w_unanchored = lint_fail_regex(r"Failed password for .+ from <HOST> port \d+");
        assert_eq!(w_unanchored.len(), 1);
        assert!(w_unanchored[0].message.contains("end with '$'"));

        // Non-greedy wildcard before <HOST> -> warning even if anchored
        let w_nongreedy = lint_fail_regex(r"Failed password for .+? from <HOST> port \d+$");
        assert_eq!(w_nongreedy.len(), 1);
        assert!(w_nongreedy[0].message.contains("non-greedy"));
    }
}
