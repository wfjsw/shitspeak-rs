use parking_lot::Mutex;
use std::{
    collections::VecDeque,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

const PACKET_OVERHEAD_BYTES: usize = 32;
const WINDOW: Duration = Duration::from_secs(1);
// Mumble advertises max_bandwidth in bits per second.
const BANDWIDTH_CHANGE_GRACE_PERIOD: Duration = Duration::from_secs(5);
const BURST_CAPACITY_MULTIPLIER: u64 = 2;
const SEVERE_WINDOW_MULTIPLIER: u64 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VoiceIngressAdmission {
    Accepted,
    Dropped,
    ProtocolViolation,
}

struct State {
    limit_bytes_per_second: u64,
    tokens: f64,
    last_refill: Instant,
    window: VecDeque<(Instant, usize)>,
    window_bytes: usize,
    severe_events: u8,
    grace_until: Instant,
}

pub(crate) struct VoiceIngressLimiter {
    state: Mutex<State>,
    violation_reported: AtomicBool,
}

impl Default for VoiceIngressLimiter {
    fn default() -> Self {
        Self::new(0)
    }
}

impl VoiceIngressLimiter {
    pub(crate) fn new(limit_bits_per_second: u32) -> Self {
        let now = Instant::now();
        let limit = Self::bytes_per_second(limit_bits_per_second);
        Self {
            state: Mutex::new(State {
                limit_bytes_per_second: limit,
                tokens: Self::burst_capacity(limit) as f64,
                last_refill: now,
                window: VecDeque::new(),
                window_bytes: 0,
                severe_events: 0,
                grace_until: now,
            }),
            violation_reported: AtomicBool::new(false),
        }
    }

    fn bytes_per_second(bits_per_second: u32) -> u64 {
        (u64::from(bits_per_second) * 5 / 4) / 8
    }

    fn burst_capacity(limit_bytes_per_second: u64) -> u64 {
        limit_bytes_per_second.saturating_mul(BURST_CAPACITY_MULTIPLIER)
    }

    /// Reset all accumulated accounting when the advertised cap changes.
    /// The grace period lets clients observe the new cap before enforcement.
    pub(crate) fn update_limit(&self, limit_bits_per_second: u32) {
        let limit = Self::bytes_per_second(limit_bits_per_second);
        let now = Instant::now();
        let mut state = self.state.lock();
        state.limit_bytes_per_second = limit;
        state.tokens = Self::burst_capacity(limit) as f64;
        state.last_refill = now;
        state.window.clear();
        state.window_bytes = 0;
        state.severe_events = 0;
        state.grace_until = now + BANDWIDTH_CHANGE_GRACE_PERIOD;
        self.violation_reported.store(false, Ordering::Release);
    }

    pub(crate) fn admit(&self, payload_len: usize) -> VoiceIngressAdmission {
        let now = Instant::now();
        let accounted = payload_len.saturating_add(PACKET_OVERHEAD_BYTES);
        let mut state = self.state.lock();
        if now < state.grace_until {
            return VoiceIngressAdmission::Accepted;
        }
        while let Some((at, bytes)) = state.window.front().copied() {
            if now.duration_since(at) > WINDOW {
                state.window.pop_front();
                state.window_bytes = state.window_bytes.saturating_sub(bytes);
            } else {
                break;
            }
        }
        state.window.push_back((now, accounted));
        state.window_bytes = state.window_bytes.saturating_add(accounted);
        let severe_limit = state
            .limit_bytes_per_second
            .saturating_mul(SEVERE_WINDOW_MULTIPLIER);
        let severe = state.window_bytes as u64 > severe_limit;
        if severe {
            state.severe_events = state.severe_events.saturating_add(1);
            if state.severe_events >= 3 && !self.violation_reported.swap(true, Ordering::AcqRel) {
                return VoiceIngressAdmission::ProtocolViolation;
            }
        } else {
            state.severe_events = 0;
        }
        let elapsed = now.duration_since(state.last_refill).as_secs_f64();
        state.tokens = (state.tokens + elapsed * state.limit_bytes_per_second as f64)
            .min(Self::burst_capacity(state.limit_bytes_per_second) as f64);
        state.last_refill = now;
        if accounted as f64 > state.tokens {
            VoiceIngressAdmission::Dropped
        } else {
            state.tokens -= accounted as f64;
            VoiceIngressAdmission::Accepted
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_limit_drops_without_panicking() {
        let limiter = VoiceIngressLimiter::new(0);
        limiter.state.lock().grace_until = Instant::now();
        assert_eq!(limiter.admit(1), VoiceIngressAdmission::Dropped);
    }

    #[test]
    fn configured_limit_uses_bit_rate_with_protocol_overhead() {
        let limiter = VoiceIngressLimiter::new(8_000);
        limiter.state.lock().grace_until = Instant::now();
        assert_eq!(limiter.admit(1_000), VoiceIngressAdmission::Accepted);
    }

    #[test]
    fn burst_headroom_delays_drops() {
        let limiter = VoiceIngressLimiter::new(8_000);
        limiter.state.lock().grace_until = Instant::now();
        assert_eq!(limiter.admit(1_300), VoiceIngressAdmission::Accepted);
        assert_eq!(limiter.admit(1_300), VoiceIngressAdmission::Dropped);
    }

    #[test]
    fn severe_requires_three_packets_above_burst_threshold() {
        let limiter = VoiceIngressLimiter::new(8_000);
        limiter.state.lock().grace_until = Instant::now();
        for _ in 0..5 {
            assert_ne!(
                limiter.admit(1_000),
                VoiceIngressAdmission::ProtocolViolation
            );
        }
        assert_eq!(
            limiter.admit(1_000),
            VoiceIngressAdmission::ProtocolViolation
        );
    }

    #[test]
    fn limit_change_resets_accounting_and_grants_grace_period() {
        let limiter = VoiceIngressLimiter::new(8_000);
        limiter.state.lock().grace_until = Instant::now();
        assert_eq!(limiter.admit(10_000), VoiceIngressAdmission::Dropped);

        limiter.update_limit(8_000);
        assert_eq!(limiter.admit(100_000), VoiceIngressAdmission::Accepted);
    }
}
