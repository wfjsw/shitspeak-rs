use std::hash::{Hash, Hasher};
use std::pin::Pin;
use std::time::Duration;

use tokio::time::{Sleep, sleep};

use crate::types::NodeIdentifier;

use super::service_level::TransportKind;

const STARTUP_PROBE_MIN_SPREAD: Duration = Duration::from_millis(500);
const STARTUP_PROBE_MAX_SPREAD: Duration = Duration::from_secs(30);

pub(crate) struct StartupBandwidthProbe {
    enabled: bool,
    done: bool,
    delay: Duration,
    sleep: Option<Pin<Box<Sleep>>>,
}

impl StartupBandwidthProbe {
    pub(crate) fn new(enabled: bool, delay: Duration) -> Self {
        Self {
            enabled,
            done: false,
            delay,
            sleep: None,
        }
    }

    pub(crate) fn arm(&mut self) {
        if !self.enabled || self.done || self.sleep.is_some() {
            return;
        }
        self.sleep = Some(Box::pin(sleep(self.delay)));
    }

    pub(crate) async fn tick(&mut self) {
        match self.sleep.as_mut() {
            Some(sleep) => sleep.as_mut().await,
            None => std::future::pending::<()>().await,
        }
    }

    pub(crate) fn complete(&mut self) {
        self.done = true;
        self.sleep = None;
    }
}

pub(crate) fn bandwidth_probe_startup_jitter(
    local: NodeIdentifier,
    peer: NodeIdentifier,
    transport: TransportKind,
    _ping_interval: Duration,
) -> Duration {
    let spread = STARTUP_PROBE_MAX_SPREAD.max(STARTUP_PROBE_MIN_SPREAD);
    let spread_nanos = spread.as_nanos().min(u128::from(u64::MAX)) as u64;
    if spread_nanos == 0 {
        return Duration::ZERO;
    }

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    "s2s-startup-bandwidth-probe-v1".hash(&mut hasher);
    local.hash(&mut hasher);
    peer.hash(&mut hasher);
    transport.hash(&mut hasher);
    Duration::from_nanos(hasher.finish() % (spread_nanos + 1))
}

pub(crate) fn stabilized_ping_interval(active: Duration, idle: Duration) -> Duration {
    if active.is_zero() || idle.is_zero() {
        return active;
    }
    idle.max(active)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_jitter_is_deterministic_and_bounded() {
        let delay_a =
            bandwidth_probe_startup_jitter(1, 2, TransportKind::Tcp, Duration::from_secs(2));
        let delay_b =
            bandwidth_probe_startup_jitter(1, 2, TransportKind::Tcp, Duration::from_secs(2));

        assert_eq!(delay_a, delay_b);
        assert!(delay_a <= STARTUP_PROBE_MAX_SPREAD);
    }

    #[test]
    fn stabilized_ping_interval_never_shortens_active_interval() {
        assert_eq!(
            stabilized_ping_interval(Duration::from_secs(2), Duration::ZERO),
            Duration::from_secs(2)
        );
        assert_eq!(
            stabilized_ping_interval(Duration::from_secs(2), Duration::from_secs(1)),
            Duration::from_secs(2)
        );
        assert_eq!(
            stabilized_ping_interval(Duration::from_secs(2), Duration::from_secs(10)),
            Duration::from_secs(10)
        );
        assert_eq!(
            stabilized_ping_interval(Duration::ZERO, Duration::from_secs(10)),
            Duration::ZERO
        );
    }
}
