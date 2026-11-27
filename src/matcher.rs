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
}
