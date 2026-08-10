//! Local strict-participant capability lifecycle.
//!
//! This state belongs to replication. The overlay receives only serialized
//! upper-layer bytes (plus deprecated rolling-upgrade fields) and does not
//! decide when a participant may advertise a protocol version.

use std::sync::Arc;

use parking_lot::Mutex;

use super::protocol::STRICT_PROTOCOL_VERSION_CURRENT;

type Publisher = dyn Fn(u32) + Send + Sync;

#[derive(Clone, Copy, Debug)]
struct ParticipantState {
    participant_enabled: bool,
    durable_state_ready: bool,
    repository_registration_ready: bool,
    /// One coordinated registration pass may promote the repository gate.
    /// Capability loss consumes the permit until an explicit new pass.
    repository_registration_rearm_permitted: bool,
    permanently_disabled: bool,
}

impl ParticipantState {
    fn advertised_version(self) -> u32 {
        if self.participant_enabled
            && self.durable_state_ready
            && self.repository_registration_ready
            && !self.permanently_disabled
        {
            STRICT_PROTOCOL_VERSION_CURRENT
        } else {
            0
        }
    }
}

pub(crate) struct StrictParticipantCapability {
    state: Mutex<ParticipantState>,
    publisher: Arc<Publisher>,
}

impl StrictParticipantCapability {
    pub(crate) fn new(
        participant_enabled: bool,
        durable_state_ready: bool,
        publisher: impl Fn(u32) + Send + Sync + 'static,
    ) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(ParticipantState {
                participant_enabled,
                durable_state_ready,
                repository_registration_ready: false,
                repository_registration_rearm_permitted: false,
                permanently_disabled: false,
            }),
            publisher: Arc::new(publisher),
        })
    }

    pub(crate) fn publish_current(&self) {
        (self.publisher)(self.protocol_version());
    }

    pub(crate) fn protocol_version(&self) -> u32 {
        self.state.lock().advertised_version()
    }

    pub(crate) fn begin_repository_registration(&self) {
        let version = {
            let mut state = self.state.lock();
            state.repository_registration_ready = false;
            state.repository_registration_rearm_permitted = true;
            state.advertised_version()
        };
        (self.publisher)(version);
    }

    pub(crate) fn update_repository_registration_ready(&self, ready: bool) -> bool {
        let version = {
            let mut state = self.state.lock();
            if ready && !state.repository_registration_ready {
                if !state.repository_registration_rearm_permitted {
                    return false;
                }
                state.repository_registration_rearm_permitted = false;
            }
            state.repository_registration_ready = ready;
            state.advertised_version()
        };
        (self.publisher)(version);
        ready
    }

    pub(crate) fn report_repository_capability_loss(&self) {
        let version = {
            let mut state = self.state.lock();
            if !state.repository_registration_ready
                && !state.repository_registration_rearm_permitted
            {
                return;
            }
            state.repository_registration_ready = false;
            state.repository_registration_rearm_permitted = false;
            state.advertised_version()
        };
        (self.publisher)(version);
    }

    pub(crate) fn update_durable_state_ready(&self, ready: bool) {
        let version = {
            let mut state = self.state.lock();
            if state.durable_state_ready == ready {
                return;
            }
            state.durable_state_ready = ready;
            state.advertised_version()
        };
        (self.publisher)(version);
    }

    pub(crate) fn disable_permanently(&self) {
        let version = {
            let mut state = self.state.lock();
            if state.permanently_disabled {
                return;
            }
            state.permanently_disabled = true;
            state.advertised_version()
        };
        (self.publisher)(version);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    fn capability(durable: bool, published: Arc<AtomicU32>) -> Arc<StrictParticipantCapability> {
        StrictParticipantCapability::new(true, durable, move |version| {
            published.store(version, Ordering::Relaxed);
        })
    }

    #[test]
    fn durable_storage_and_coordinated_registration_are_both_required() {
        let published = Arc::new(AtomicU32::new(99));
        let capability = capability(false, published.clone());
        capability.publish_current();
        assert_eq!(published.load(Ordering::Relaxed), 0);

        capability.begin_repository_registration();
        assert!(capability.update_repository_registration_ready(true));
        assert_eq!(capability.protocol_version(), 0);

        capability.update_durable_state_ready(true);
        assert_eq!(
            capability.protocol_version(),
            STRICT_PROTOCOL_VERSION_CURRENT
        );
        assert_eq!(
            published.load(Ordering::Relaxed),
            STRICT_PROTOCOL_VERSION_CURRENT
        );
    }

    #[test]
    fn repository_loss_requires_an_explicit_rearm() {
        let capability = capability(true, Arc::new(AtomicU32::new(0)));
        capability.begin_repository_registration();
        assert!(capability.update_repository_registration_ready(true));
        assert_eq!(
            capability.protocol_version(),
            STRICT_PROTOCOL_VERSION_CURRENT
        );

        capability.report_repository_capability_loss();
        assert_eq!(capability.protocol_version(), 0);
        assert!(!capability.update_repository_registration_ready(true));
        assert_eq!(capability.protocol_version(), 0);

        capability.begin_repository_registration();
        assert!(capability.update_repository_registration_ready(true));
        assert_eq!(
            capability.protocol_version(),
            STRICT_PROTOCOL_VERSION_CURRENT
        );
    }

    #[test]
    fn terminal_failure_is_sticky_across_storage_recovery() {
        let capability = capability(true, Arc::new(AtomicU32::new(0)));
        capability.begin_repository_registration();
        assert!(capability.update_repository_registration_ready(true));
        capability.disable_permanently();
        capability.update_durable_state_ready(false);
        capability.update_durable_state_ready(true);
        assert_eq!(capability.protocol_version(), 0);
    }

    #[test]
    fn disabled_participant_never_advertises_a_participant_version() {
        let capability = StrictParticipantCapability::new(false, true, |_| {});
        capability.begin_repository_registration();
        assert!(capability.update_repository_registration_ready(true));
        assert_eq!(capability.protocol_version(), 0);
    }
}
