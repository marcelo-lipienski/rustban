use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use crate::ip::IpKey;

/// Ephemeral in-memory failure counter for a single jail.
///
/// Tracks only *unbanned* failing IPs within `find_time`. Once an IP hits `max_retries`,
/// it is evicted from this map and handed off to `nftables` (which owns ban expiration).
///
/// Eviction when `max_tracked_ips` is reached is amortized O(1) via an age queue so
/// distributed IP-spoofing floods cannot cause O(N²) CPU stalls.
#[derive(Debug)]
pub struct FailureTracker {
    find_time: Duration,
    max_retries: usize,
    max_tracked_ips: usize,
    hits: HashMap<IpKey, VecDeque<Instant>>,
    order: VecDeque<(IpKey, Instant)>,
    last_prune: Option<Instant>,
}

impl FailureTracker {
    pub fn new(find_time: Duration, max_retries: usize, max_tracked_ips: usize) -> Self {
        Self {
            find_time,
            max_retries: max_retries.max(1),
            max_tracked_ips: max_tracked_ips.max(1),
            hits: HashMap::new(),
            order: VecDeque::new(),
            last_prune: None,
        }
    }

    /// Record a failed attempt at `now`.
    /// Returns `true` if `key` reached `max_retries` within `find_time` (and removes it from RAM).
    pub fn record_failure(&mut self, key: IpKey, now: Instant) -> bool {
        if self.max_retries <= 1 {
            self.hits.remove(&key);
            return true;
        }

        if !self.hits.contains_key(&key) && self.hits.len() >= self.max_tracked_ips {
            // Rate-limit full-table sweeps to avoid O(N²) CPU DoS under high-rate IP floods.
            let should_prune = self
                .last_prune
                .map(|lp| now.saturating_duration_since(lp) >= Duration::from_secs(1))
                .unwrap_or(true);
            if should_prune {
                self.prune(now);
            }
            if self.hits.len() >= self.max_tracked_ips {
                self.evict_oldest_o1();
            }
        }

        let cutoff = now.checked_sub(self.find_time);
        let entry = self
            .hits
            .entry(key)
            .or_insert_with(|| VecDeque::with_capacity(self.max_retries));

        if let Some(cutoff) = cutoff {
            while let Some(&front) = entry.front() {
                if front < cutoff {
                    entry.pop_front();
                } else {
                    break;
                }
            }
        }

        entry.push_back(now);
        if entry.len() >= self.max_retries {
            self.hits.remove(&key);
            return true;
        }

        self.order.push_back((key, now));
        // Bound stale tombstone accumulation in `order`.
        let max_order = self.max_tracked_ips.saturating_mul(4).max(64);
        if self.order.len() > max_order {
            self.compact_order();
        }
        false
    }

    /// Remove stale timestamps and empty IP entries older than `find_time`.
    pub fn prune(&mut self, now: Instant) {
        self.last_prune = Some(now);
        let Some(cutoff) = now.checked_sub(self.find_time) else {
            return;
        };
        self.hits.retain(|_, times| {
            while let Some(&front) = times.front() {
                if front < cutoff {
                    times.pop_front();
                } else {
                    break;
                }
            }
            !times.is_empty()
        });
        self.compact_order();
    }

    /// Amortized O(1) eviction of the least-recently-seen IP using the age queue.
    fn evict_oldest_o1(&mut self) {
        while let Some((candidate, ts)) = self.order.pop_front() {
            let is_live = self.hits.get(&candidate).and_then(|q| q.back()).copied() == Some(ts);
            if is_live {
                self.hits.remove(&candidate);
                return;
            }
        }
        // Fallback if queue was somehow drained while map still full.
        if let Some(&any_key) = self.hits.keys().next() {
            self.hits.remove(&any_key);
        }
    }

    fn compact_order(&mut self) {
        self.order
            .retain(|(k, ts)| self.hits.get(k).and_then(|q| q.back()).copied() == Some(*ts));
    }

    pub fn tracked_len(&self) -> usize {
        self.hits.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn triggers_ban_and_forgets_ip() {
        let mut tracker = FailureTracker::new(Duration::from_secs(60), 3, 100);
        let ip = IpKey::V4("203.0.113.10".parse().unwrap());
        let t0 = Instant::now();

        assert!(!tracker.record_failure(ip, t0));
        assert!(!tracker.record_failure(ip, t0 + Duration::from_secs(10)));
        assert_eq!(tracker.tracked_len(), 1);
        assert!(tracker.record_failure(ip, t0 + Duration::from_secs(20)));
        assert_eq!(tracker.tracked_len(), 0);
    }

    #[test]
    fn expires_old_attempts_outside_find_time() {
        let mut tracker = FailureTracker::new(Duration::from_secs(30), 3, 100);
        let ip = IpKey::V4("203.0.113.11".parse().unwrap());
        let t0 = Instant::now();

        assert!(!tracker.record_failure(ip, t0));
        assert!(!tracker.record_failure(ip, t0 + Duration::from_secs(10)));
        assert!(!tracker.record_failure(ip, t0 + Duration::from_secs(35)));
        assert!(tracker.record_failure(ip, t0 + Duration::from_secs(36)));
    }

    #[test]
    fn bounds_memory_and_cpu_under_ip_flood() {
        let mut tracker = FailureTracker::new(Duration::from_secs(600), 5, 1000);
        let t0 = Instant::now();
        let start = Instant::now();
        for i in 0..50_000u32 {
            let ip = IpKey::V4(std::net::Ipv4Addr::from(0x0b00_0000u32 + i));
            tracker.record_failure(ip, t0 + Duration::from_micros(i as u64));
        }
        assert!(tracker.tracked_len() <= 1000);
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "eviction took too long: {:?}",
            start.elapsed()
        );
    }
}
