use std::fmt;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};

/// Normalized ban target stored in nftables O(1) hash sets:
/// - IPv4: exact `/32` host address
/// - IPv6: `/64` network prefix (lower 64 host bits zeroed)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum IpKey {
    V4(Ipv4Addr),
    V6Prefix(Ipv6Addr),
}

impl IpKey {
    /// Normalize an `IpAddr` into an `IpKey`:
    /// - IPv4-mapped IPv6 (`::ffff:a.b.c.d`) is converted to IPv4 so it matches IPv4 wire packets.
    /// - Native IPv6 is masked to its `/64` prefix.
    pub fn from_ip(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => IpKey::V4(v4),
            IpAddr::V6(v6) => {
                if let Some(v4) = v6.to_ipv4_mapped() {
                    IpKey::V4(v4)
                } else {
                    IpKey::V6Prefix(mask_v6_64(v6))
                }
            }
        }
    }

    /// Parse an IP address or IPv6 `/64` notation (e.g. `2001:db8:abcd:1234::/64`) into an `IpKey`.
    pub fn parse_user_input(s: &str) -> Result<Self, String> {
        let trimmed = s.trim().trim_start_matches('[').trim_end_matches(']');
        if let Ok(ip) = IpAddr::from_str(trimmed) {
            return Ok(Self::from_ip(ip));
        }
        if let Ok(net) = IpNet::from_str(trimmed) {
            return match net {
                IpNet::V4(v4) if v4.prefix_len() == 32 => Ok(IpKey::V4(v4.addr())),
                IpNet::V6(v6) if v6.prefix_len() >= 64 => {
                    Ok(Self::from_ip(IpAddr::V6(v6.addr())))
                }
                _ => Err(format!(
                    "unsupported CIDR '{s}': rustban uses O(1) host/64 sets (IPv4 /32 or IPv6 /64..=/128)"
                )),
            };
        }
        Err(format!("invalid IP address: '{s}'"))
    }

    /// Returns `true` for non-routable / special-use targets that must NEVER be banned:
    /// - IPv4: `0.0.0.0/8`, `127.0.0.0/8`, `224.0.0.0/4`, `240.0.0.0/4` (incl. `255.255.255.255`)
    /// - IPv6: `::/64` (unspecified, loopback `::1`, IPv4-compatible), `fe80::/10`, `ff00::/8`
    pub fn is_unbannable_special(&self) -> bool {
        match *self {
            IpKey::V4(v4) => is_unbannable_v4(v4),
            IpKey::V6Prefix(v6) => is_unbannable_v6_prefix(v6),
        }
    }

    /// Exact address representation used as the element value in `nftables`.
    pub fn nft_element(&self) -> String {
        match self {
            IpKey::V4(v4) => v4.to_string(),
            IpKey::V6Prefix(v6) => v6.to_string(),
        }
    }

    /// Human-readable representation (shows `/64` suffix for IPv6 prefixes).
    pub fn display_cidr(&self) -> String {
        match self {
            IpKey::V4(v4) => v4.to_string(),
            IpKey::V6Prefix(v6) => format!("{v6}/64"),
        }
    }

    pub fn is_v4(&self) -> bool {
        matches!(self, IpKey::V4(_))
    }

    pub fn as_ip(&self) -> IpAddr {
        match *self {
            IpKey::V4(v4) => IpAddr::V4(v4),
            IpKey::V6Prefix(v6) => IpAddr::V6(v6),
        }
    }
}

impl fmt::Display for IpKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.display_cidr())
    }
}

pub fn is_unbannable_special(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_unbannable_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                is_unbannable_v4(v4)
            } else {
                is_unbannable_v6_prefix(mask_v6_64(v6))
            }
        }
    }
}

fn is_unbannable_v4(v4: Ipv4Addr) -> bool {
    let first = v4.octets()[0];
    // 0.0.0.0/8 (this network / unspecified), 127.0.0.0/8 (loopback),
    // 224.0.0.0/4 (multicast), 240.0.0.0/4 (reserved + 255.255.255.255 broadcast)
    first == 0 || first == 127 || first >= 224
}

fn is_unbannable_v6_prefix(prefix: Ipv6Addr) -> bool {
    let segs = prefix.segments();
    // ::/64 (unspecified, ::1 loopback, IPv4-compatible)
    let is_zero_64 = segs[0] == 0 && segs[1] == 0 && segs[2] == 0 && segs[3] == 0;
    // fe80::/10 (link-local)
    let is_link_local = (segs[0] & 0xffc0) == 0xfe80;
    // ff00::/8 (multicast)
    let is_multicast = (segs[0] & 0xff00) == 0xff00;
    is_zero_64 || is_link_local || is_multicast
}

/// Mask an IPv6 address down to its `/64` network prefix (clearing the lower 64 bits).
pub fn mask_v6_64(v6: Ipv6Addr) -> Ipv6Addr {
    let bits = u128::from(v6) & 0xffff_ffff_ffff_ffff_0000_0000_0000_0000u128;
    Ipv6Addr::from(bits)
}

/// Parse an IP or CIDR string into an `IpNet`. Single IPs become `/32` or `/128`.
pub fn parse_cidr_or_ip(s: &str) -> Result<IpNet, String> {
    let trimmed = s.trim();
    if let Ok(net) = IpNet::from_str(trimmed) {
        return Ok(net.trunc());
    }
    if let Ok(ip) = IpAddr::from_str(trimmed) {
        return Ok(match ip {
            IpAddr::V4(v4) => IpNet::V4(Ipv4Net::new(v4, 32).expect("valid /32")),
            IpAddr::V6(v6) => {
                if let Some(v4) = v6.to_ipv4_mapped() {
                    IpNet::V4(Ipv4Net::new(v4, 32).expect("valid /32"))
                } else {
                    IpNet::V6(Ipv6Net::new(v6, 128).expect("valid /128"))
                }
            }
        });
    }
    Err(format!("invalid IP or CIDR '{s}'"))
}

/// Discover all local interface IPv4 and IPv6 addresses assigned to the current host/netns
/// by reading Linux procfs (`/proc/net/fib_trie` and `/proc/net/if_inet6`) with zero C FFI.
pub fn discover_local_interface_ips() -> Vec<IpAddr> {
    let mut ips = Vec::new();
    if let Ok(content) = fs::read_to_string("/proc/net/fib_trie") {
        ips.extend(
            parse_fib_trie_local_v4(&content)
                .into_iter()
                .map(IpAddr::V4),
        );
    }
    if let Ok(content) = fs::read_to_string("/proc/net/if_inet6") {
        ips.extend(parse_if_inet6(&content).into_iter().map(IpAddr::V6));
    }
    ips.sort();
    ips.dedup();
    ips
}

/// Parse `/32 host LOCAL` IPv4 interface addresses from `/proc/net/fib_trie`.
pub fn parse_fib_trie_local_v4(content: &str) -> Vec<Ipv4Addr> {
    let mut result = Vec::new();
    let mut last_ip: Option<Ipv4Addr> = None;

    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed
            .strip_prefix("|-- ")
            .or_else(|| trimmed.strip_prefix("+-- "))
        {
            let token = rest.split_whitespace().next().unwrap_or("");
            last_ip = Ipv4Addr::from_str(token).ok();
        } else if trimmed == "/32 host LOCAL" {
            if let Some(ip) = last_ip {
                result.push(ip);
            }
        }
    }

    result.sort();
    result.dedup();
    result
}

/// Parse assigned local IPv6 interface addresses from `/proc/net/if_inet6`.
pub fn parse_if_inet6(content: &str) -> Vec<Ipv6Addr> {
    let mut result = Vec::new();
    for line in content.lines() {
        if let Some(hex) = line.split_whitespace().next() {
            if hex.len() == 32 {
                if let Ok(bits) = u128::from_str_radix(hex, 16) {
                    result.push(Ipv6Addr::from(bits));
                }
            }
        }
    }
    result.sort();
    result.dedup();
    result
}

/// Collection of whitelisted IPv4/IPv6 CIDR prefixes.
#[derive(Debug, Clone, Default)]
pub struct IgnoreList {
    v4: Vec<Ipv4Net>,
    v6: Vec<Ipv6Net>,
}

impl IgnoreList {
    pub fn from_strings(entries: &[String], include_defaults: bool) -> Result<Self, String> {
        Self::from_options(entries, include_defaults, false)
    }

    pub fn from_options(
        entries: &[String],
        include_defaults: bool,
        ignore_self: bool,
    ) -> Result<Self, String> {
        let mut list = Self::default();
        if include_defaults {
            list.push_net(IpNet::V4(
                Ipv4Net::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap(),
            ));
            list.push_net(IpNet::V6(Ipv6Net::new(Ipv6Addr::LOCALHOST, 128).unwrap()));
            list.push_net(IpNet::V6(
                Ipv6Net::new(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10).unwrap(),
            ));
        }
        if ignore_self {
            for ip in discover_local_interface_ips() {
                list.push_ip(ip);
            }
        }
        for entry in entries {
            let net = parse_cidr_or_ip(entry)?;
            list.push_net(net);
        }
        list.normalize();
        Ok(list)
    }

    pub fn push_ip(&mut self, ip: IpAddr) {
        match ip {
            IpAddr::V4(v4) => self.v4.push(Ipv4Net::new(v4, 32).expect("valid /32")),
            IpAddr::V6(v6) => {
                if let Some(v4) = v6.to_ipv4_mapped() {
                    self.v4.push(Ipv4Net::new(v4, 32).expect("valid /32"));
                } else {
                    self.v6.push(Ipv6Net::new(v6, 128).expect("valid /128"));
                }
            }
        }
        self.normalize();
    }

    fn push_net(&mut self, net: IpNet) {
        match net {
            IpNet::V4(n) => self.v4.push(n),
            IpNet::V6(n) => self.v6.push(n),
        }
    }

    fn normalize(&mut self) {
        self.v4.sort();
        self.v4.dedup();
        self.v6.sort();
        self.v6.dedup();
    }

    /// Check whether a raw `IpAddr` matches any ignored CIDR.
    pub fn contains_ip(&self, ip: IpAddr) -> bool {
        let normalized = match ip {
            IpAddr::V6(v6) => v6
                .to_ipv4_mapped()
                .map(IpAddr::V4)
                .unwrap_or(IpAddr::V6(v6)),
            other => other,
        };
        match normalized {
            IpAddr::V4(v4) => self.v4.iter().any(|net| net.contains(&v4)),
            IpAddr::V6(v6) => self.v6.iter().any(|net| net.contains(&v6)),
        }
    }

    /// Check whether an `IpKey` matches OR overlaps any ignored CIDR.
    ///
    /// For IPv6 `/64` keys, if *any* whitelisted CIDR (including a `/128` host/admin IP or `::1/128`)
    /// lies inside that `/64` prefix, we return `true` so banning the `/64` cannot bypass the
    /// whitelist or cause collateral lockout of a whitelisted IPv6 host.
    pub fn contains_key(&self, key: IpKey) -> bool {
        match key {
            IpKey::V4(v4) => self.v4.iter().any(|net| net.contains(&v4)),
            IpKey::V6Prefix(prefix) => {
                let prefix_net = Ipv6Net::new(prefix, 64).expect("valid /64");
                self.v6
                    .iter()
                    .any(|net| net.contains(&prefix) || prefix_net.contains(&net.addr()))
            }
        }
    }

    pub fn v4_cidrs(&self) -> &[Ipv4Net] {
        &self.v4
    }

    pub fn v6_cidrs(&self) -> &[Ipv6Net] {
        &self.v6
    }

    pub fn extend_from(&mut self, other: &IgnoreList) {
        self.v4.extend_from_slice(&other.v4);
        self.v6.extend_from_slice(&other.v6);
        self.normalize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_ipv4_and_ipv6_64_and_mapped() {
        let v4 = IpKey::from_ip("203.0.113.42".parse().unwrap());
        assert_eq!(v4, IpKey::V4("203.0.113.42".parse().unwrap()));
        assert_eq!(v4.display_cidr(), "203.0.113.42");

        let v6 = IpKey::from_ip("2001:db8:abcd:1234:dead:beef:cafe:1".parse().unwrap());
        assert_eq!(v6, IpKey::V6Prefix("2001:db8:abcd:1234::".parse().unwrap()));
        assert_eq!(v6.nft_element(), "2001:db8:abcd:1234::");
        assert_eq!(v6.display_cidr(), "2001:db8:abcd:1234::/64");

        let mapped = IpKey::from_ip("::ffff:198.51.100.7".parse().unwrap());
        assert_eq!(mapped, IpKey::V4("198.51.100.7".parse().unwrap()));
    }

    #[test]
    fn ignore_list_protects_overlapping_v6_128_and_loopback() {
        let ignores = IgnoreList::from_strings(
            &[
                "10.0.0.0/8".into(),
                "2001:db8:1:2::admin".replace("admin", "cafe"),
            ],
            true,
        )
        .unwrap();

        // Loopback IPv6 ::1 and sibling ::2 in ::/64 must both match contains_key
        assert!(ignores.contains_key(IpKey::from_ip("::1".parse().unwrap())));
        assert!(ignores.contains_key(IpKey::from_ip("::2".parse().unwrap())));
        // A /128 admin IP protects its /64 key against collateral banning
        assert!(ignores.contains_key(IpKey::from_ip("2001:db8:1:2::cafe".parse().unwrap())));
        assert!(ignores.contains_key(IpKey::from_ip("2001:db8:1:2::9999".parse().unwrap())));
        assert!(!ignores.contains_key(IpKey::from_ip("2001:db8:1:3::1".parse().unwrap())));
    }

    #[test]
    fn parses_proc_fib_trie_and_if_inet6() {
        let fib = r#"
Local:
  +-- 0.0.0.0/0 2 0 2
     |-- 127.0.0.0
        /8 host LOCAL
     |-- 127.0.0.1
        /32 host LOCAL
     |-- 172.17.0.2
        /32 host LOCAL
     |-- 172.17.255.255
        /32 link BROADCAST
"#;
        let v4s = parse_fib_trie_local_v4(fib);
        assert_eq!(
            v4s,
            vec![
                "127.0.0.1".parse::<Ipv4Addr>().unwrap(),
                "172.17.0.2".parse::<Ipv4Addr>().unwrap()
            ]
        );

        let inet6 = "20010db8abcd12340000000000000002 02 40 00 80 eth0\n\
                     00000000000000000000000000000001 01 80 10 80 lo\n";
        let v6s = parse_if_inet6(inet6);
        assert_eq!(
            v6s,
            vec![
                "::1".parse::<Ipv6Addr>().unwrap(),
                "2001:db8:abcd:1234::2".parse::<Ipv6Addr>().unwrap()
            ]
        );
    }

    #[test]
    fn rejects_special_unbannable_addresses() {
        for addr in [
            "0.0.0.0",
            "0.1.2.3",
            "127.0.0.1",
            "224.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::2",
            "fe80::1",
            "ff02::1",
        ] {
            let ip: IpAddr = addr.parse().unwrap();
            assert!(
                is_unbannable_special(ip),
                "expected {addr} to be unbannable"
            );
            assert!(
                IpKey::from_ip(ip).is_unbannable_special(),
                "expected key for {addr} to be unbannable"
            );
        }
        assert!(!is_unbannable_special("203.0.113.42".parse().unwrap()));
        assert!(!is_unbannable_special("2001:db8:1::1".parse().unwrap()));
    }
}
