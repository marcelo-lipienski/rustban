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

/// Optional per-jail bounded in-memory repeat-offender strike tracker.
///
/// Escalates ban duration as `min(base_ban_time * multiplier^(strike - 1), max_ban_time)`
/// while repeat bans occur within `window`. Only instantiated when `ban_time_multiplier > 1.0`
/// (zero overhead when disabled). Uses the same amortized O(1) eviction bound as `FailureTracker`.
#[derive(Debug)]
pub struct EscalationTracker {
    base_ban_time: Duration,
    multiplier: f64,
    max_ban_time: Duration,
    window: Duration,
    max_tracked_ips: usize,
    strikes: HashMap<IpKey, (u32, Instant)>,
    order: VecDeque<(IpKey, Instant)>,
    last_prune: Option<Instant>,
}

impl EscalationTracker {
    pub fn new(
        base_ban_time: Duration,
        multiplier: f64,
        max_ban_time: Duration,
        window: Duration,
        max_tracked_ips: usize,
    ) -> Self {
        Self {
            base_ban_time,
            multiplier: multiplier.max(1.0),
            max_ban_time: max_ban_time.max(base_ban_time),
            window,
            max_tracked_ips: max_tracked_ips.max(1),
            strikes: HashMap::new(),
            order: VecDeque::new(),
            last_prune: None,
        }
    }

    /// Record a ban for `key` at `now` and return `(escalated_duration, strike_count)`.
    pub fn record_ban(&mut self, key: IpKey, now: Instant) -> (Duration, u32) {
        if !self.strikes.contains_key(&key) && self.strikes.len() >= self.max_tracked_ips {
            let should_prune = self
                .last_prune
                .map(|lp| now.saturating_duration_since(lp) >= Duration::from_secs(1))
                .unwrap_or(true);
            if should_prune {
                self.prune(now);
            }
            if self.strikes.len() >= self.max_tracked_ips {
                self.evict_oldest_o1();
            }
        }

        let cutoff = now.checked_sub(self.window);
        let strike = match self.strikes.get(&key).copied() {
            Some((prev_count, prev_ts)) if cutoff.map(|c| prev_ts >= c).unwrap_or(true) => {
                prev_count.saturating_add(1)
            }
            _ => 1,
        };

        self.strikes.insert(key, (strike, now));
        self.order.push_back((key, now));

        let max_order = self.max_tracked_ips.saturating_mul(4).max(64);
        if self.order.len() > max_order {
            self.compact_order();
        }

        let duration = self.compute_duration(strike);
        (duration, strike)
    }

    fn compute_duration(&self, strike: u32) -> Duration {
        let base_secs = self.base_ban_time.as_secs().max(1) as f64;
        let max_secs = self.max_ban_time.as_secs().max(1) as f64;
        let exp = strike.saturating_sub(1).min(64) as i32;
        let scaled = base_secs * self.multiplier.powi(exp);
        let clamped = if scaled.is_finite() {
            scaled.min(max_secs).max(base_secs)
        } else {
            max_secs
        };
        Duration::from_secs(clamped.round() as u64)
    }

    /// Remove strike entries older than `window`.
    pub fn prune(&mut self, now: Instant) {
        self.last_prune = Some(now);
        let Some(cutoff) = now.checked_sub(self.window) else {
            return;
        };
        self.strikes.retain(|_, (_, ts)| *ts >= cutoff);
        self.compact_order();
    }

    fn evict_oldest_o1(&mut self) {
        while let Some((candidate, ts)) = self.order.pop_front() {
            let is_live = self.strikes.get(&candidate).map(|(_, t)| *t) == Some(ts);
            if is_live {
                self.strikes.remove(&candidate);
                return;
            }
        }
        if let Some(&any_key) = self.strikes.keys().next() {
            self.strikes.remove(&any_key);
        }
    }

    fn compact_order(&mut self) {
        self.order
            .retain(|(k, ts)| self.strikes.get(k).map(|(_, t)| *t) == Some(*ts));
    }

    pub fn tracked_len(&self) -> usize {
        self.strikes.len()
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

    #[test]
    fn escalation_tracker_scales_clamps_decays_and_bounds_flood() {
        let mut esc = EscalationTracker::new(
            Duration::from_secs(60),
            2.0,
            Duration::from_secs(200),
            Duration::from_secs(600),
            500,
        );
        let ip = IpKey::V4("203.0.113.50".parse().unwrap());
        let t0 = Instant::now();

        assert_eq!(esc.record_ban(ip, t0), (Duration::from_secs(60), 1));
        assert_eq!(
            esc.record_ban(ip, t0 + Duration::from_secs(10)),
            (Duration::from_secs(120), 2)
        );
        // 60 * 2^2 = 240 -> clamped to max 200
        assert_eq!(
            esc.record_ban(ip, t0 + Duration::from_secs(20)),
            (Duration::from_secs(200), 3)
        );
        assert_eq!(
            esc.record_ban(ip, t0 + Duration::from_secs(30)),
            (Duration::from_secs(200), 4)
        );

        // After window expires, decays back to strike 1 (base ban_time)
        assert_eq!(
            esc.record_ban(ip, t0 + Duration::from_secs(700)),
            (Duration::from_secs(60), 1)
        );

        // Flood bounding stays <= cap in O(1)
        let start = Instant::now();
        for i in 0..20_000u32 {
            let k = IpKey::V4(std::net::Ipv4Addr::from(0x0c00_0000u32 + i));
            esc.record_ban(
                k,
                t0 + Duration::from_secs(701) + Duration::from_micros(i as u64),
            );
        }
        assert!(esc.tracked_len() <= 500);
        assert!(start.elapsed() < Duration::from_secs(2));
    }
}
