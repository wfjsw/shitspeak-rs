use std::collections::HashMap;

use super::NodeId;

#[derive(Debug, Clone, Copy)]
pub struct FrameGuard {
    pub max_frame_bytes: usize,
}

impl Default for FrameGuard {
    fn default() -> Self {
        Self {
            max_frame_bytes: 256 * 1024,
        }
    }
}

impl FrameGuard {
    pub fn validate(&self, frame_len: usize) -> bool {
        frame_len <= self.max_frame_bytes
    }
}

#[derive(Debug, Clone)]
pub struct PeerRateLimiter {
    pub burst_limit: u32,
    pub refill_per_sec: u32,
    buckets: HashMap<NodeId, (u32, u64)>,
}

impl PeerRateLimiter {
    pub fn new(burst_limit: u32, refill_per_sec: u32) -> Self {
        Self {
            burst_limit,
            refill_per_sec,
            buckets: HashMap::new(),
        }
    }

    pub fn allow(&mut self, peer: NodeId, now_ms: u64) -> bool {
        let (tokens, last_ms) = self
            .buckets
            .entry(peer)
            .or_insert((self.burst_limit, now_ms));

        let elapsed_ms = now_ms.saturating_sub(*last_ms);
        let refill = ((elapsed_ms as u128 * self.refill_per_sec as u128) / 1000) as u32;
        *tokens = (*tokens).saturating_add(refill).min(self.burst_limit);
        *last_ms = now_ms;

        if *tokens == 0 {
            return false;
        }

        *tokens -= 1;
        true
    }
}

#[derive(Debug, Clone)]
pub struct FailureCircuitBreaker {
    pub failure_threshold: u32,
    pub open_ms: u64,
    state: HashMap<NodeId, (u32, u64)>,
}

impl FailureCircuitBreaker {
    pub fn new(failure_threshold: u32, open_ms: u64) -> Self {
        Self {
            failure_threshold,
            open_ms,
            state: HashMap::new(),
        }
    }

    pub fn report_success(&mut self, peer: NodeId) {
        self.state.remove(&peer);
    }

    pub fn report_failure(&mut self, peer: NodeId, now_ms: u64) {
        let (count, opened_until_ms) = self.state.entry(peer).or_insert((0, 0));
        *count = count.saturating_add(1);
        if *count >= self.failure_threshold {
            *opened_until_ms = now_ms.saturating_add(self.open_ms);
        }
    }

    pub fn is_open(&self, peer: NodeId, now_ms: u64) -> bool {
        self.state
            .get(&peer)
            .map(|(_, opened_until_ms)| now_ms < *opened_until_ms)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_guard_enforces_max() {
        let guard = FrameGuard { max_frame_bytes: 10 };
        assert!(guard.validate(10));
        assert!(!guard.validate(11));
    }

    #[test]
    fn peer_rate_limiter_refills_over_time() {
        let mut limiter = PeerRateLimiter::new(2, 1);
        assert!(limiter.allow(1, 0));
        assert!(limiter.allow(1, 0));
        assert!(!limiter.allow(1, 0));
        assert!(limiter.allow(1, 1000));
    }

    #[test]
    fn circuit_breaker_opens_and_closes() {
        let mut breaker = FailureCircuitBreaker::new(2, 100);
        breaker.report_failure(7, 10);
        assert!(!breaker.is_open(7, 11));
        breaker.report_failure(7, 20);
        assert!(breaker.is_open(7, 50));
        assert!(!breaker.is_open(7, 130));
        breaker.report_success(7);
        assert!(!breaker.is_open(7, 30));
    }
}
