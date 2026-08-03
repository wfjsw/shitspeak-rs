//! Token-bucket (leaky bucket with burst) rate limiting primitives.
//!
//! A [`TokenBucket`] allows a burst of up to `burst` tokens immediately and
//! then refills continuously at `rate_per_second`. [`KeyedRateLimiter`] maps
//! arbitrary keys (source IP, session id, …) to independent buckets with
//! bounded memory and O(1) eviction.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Mutex;
use std::time::Instant;

/// A single token bucket: `burst` initial capacity, refilled continuously at
/// `rate_per_second` tokens per second.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    capacity: f64,
    tokens: f64,
    refill_per_second: f64,
    last_refill: Instant,
}

impl TokenBucket {
    /// Create a bucket allowing `burst` tokens immediately, refilling at
    /// `rate_per_second` tokens per second.
    ///
    /// # Panics
    ///
    /// Panics if either value is not positive and finite.
    pub fn new(rate_per_second: f64, burst: f64) -> Self {
        assert!(
            rate_per_second.is_finite() && rate_per_second > 0.0,
            "rate_per_second must be positive and finite"
        );
        assert!(
            burst.is_finite() && burst > 0.0,
            "burst must be positive and finite"
        );
        Self {
            capacity: burst,
            tokens: burst,
            refill_per_second: rate_per_second,
            last_refill: Instant::now(),
        }
    }

    /// Try to consume `n` tokens, returning `false` if insufficient tokens
    /// are available. The bucket is refilled by elapsed time first.
    pub fn try_acquire_n(&mut self, n: f64) -> bool {
        self.refill();
        if self.tokens >= n {
            self.tokens -= n;
            true
        } else {
            false
        }
    }

    /// Try to consume a single token.
    pub fn try_acquire(&mut self) -> bool {
        self.try_acquire_n(1.0)
    }

    /// Refill the bucket based on elapsed time since the last refill.
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        if elapsed > 0.0 {
            self.tokens = (self.tokens + elapsed * self.refill_per_second).min(self.capacity);
            self.last_refill = now;
        }
    }
}

/// A rate limiter keyed by an arbitrary hashable key (source IP, session id,
/// node id, …). Independent buckets per key, memory bounded at `max_entries`.
///
/// When the map is full, an existing entry is evicted in O(1) (the map's
/// iteration order is not meaningful); a later request for that key simply
/// starts a fresh full bucket, so eviction never causes a false rejection.
/// O(1) eviction matters because several limiters are keyed by *source IP of
/// spoofable packets* (UDP ping, S2S key exchange): an LRU scan per new key
/// would let a flood of distinct spoofed IPs turn the limiter itself into a
/// CPU hotspot.
///
/// The internal lock is a `std::sync::Mutex` held only for a few nanoseconds
/// of arithmetic, so it is safe to call from async contexts.
#[derive(Debug)]
pub struct KeyedRateLimiter<K> {
    buckets: Mutex<HashMap<K, TokenBucket>>,
    rate_per_second: f64,
    burst: f64,
    max_entries: usize,
}

impl<K: Eq + Hash + Clone> KeyedRateLimiter<K> {
    /// Create a limiter with per-key buckets of `burst` capacity refilling at
    /// `rate_per_second` tokens per second, retaining at most `max_entries`
    /// keys.
    pub fn new(rate_per_second: f64, burst: f64, max_entries: usize) -> Self {
        assert!(max_entries > 0, "max_entries must be positive");
        Self {
            buckets: Mutex::new(HashMap::new()),
            rate_per_second,
            burst,
            max_entries,
        }
    }

    /// Try to consume one token for `key`. The first call for a new key
    /// succeeds (the fresh bucket is full) unless the map is full, in which
    /// case an existing entry is evicted first.
    pub fn try_acquire(&self, key: &K) -> bool {
        let mut buckets = match self.buckets.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        match buckets.get_mut(key) {
            Some(bucket) => bucket.try_acquire(),
            None => {
                if buckets.len() >= self.max_entries {
                    if let Some(evicted_key) = buckets.keys().next().cloned() {
                        buckets.remove(&evicted_key);
                    }
                }
                let mut bucket = TokenBucket::new(self.rate_per_second, self.burst);
                let acquired = bucket.try_acquire();
                buckets.insert(key.clone(), bucket);
                acquired
            }
        }
    }

    /// Number of tracked keys (for diagnostics/tests).
    pub fn len(&self) -> usize {
        match self.buckets.lock() {
            Ok(guard) => guard.len(),
            Err(poisoned) => poisoned.into_inner().len(),
        }
    }

    /// Whether no keys are currently tracked.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn token_bucket_allows_burst_then_refills() {
        let mut bucket = TokenBucket::new(1.0, 3.0);
        assert!(bucket.try_acquire());
        assert!(bucket.try_acquire());
        assert!(bucket.try_acquire());
        // Burst exhausted; no tokens yet.
        assert!(!bucket.try_acquire());
    }

    #[test]
    fn token_bucket_refills_over_time() {
        let mut bucket = TokenBucket::new(10.0, 1.0);
        assert!(bucket.try_acquire());
        assert!(!bucket.try_acquire());
        std::thread::sleep(Duration::from_millis(200));
        // ~2 tokens refilled (10/s * 0.2s), capped at burst 1.
        assert!(bucket.try_acquire());
        assert!(!bucket.try_acquire());
    }

    #[test]
    fn keyed_limiter_isolates_keys() {
        let limiter = KeyedRateLimiter::new(1.0, 1.0, 16);
        assert!(limiter.try_acquire(&"a"));
        assert!(!limiter.try_acquire(&"a"));
        assert!(limiter.try_acquire(&"b"));
        assert_eq!(limiter.len(), 2);
    }

    #[test]
    fn keyed_limiter_stays_bounded_when_full() {
        let limiter = KeyedRateLimiter::new(1.0, 1.0, 2);
        assert!(limiter.try_acquire(&"a"));
        assert!(limiter.try_acquire(&"b"));
        // Map full: a flood of new keys is absorbed without growing the map,
        // and every insert still succeeds (fresh bucket on insert).
        for key in ["c", "d", "e", "f"] {
            assert!(limiter.try_acquire(&key));
            assert!(limiter.len() <= 2);
        }
    }
}
