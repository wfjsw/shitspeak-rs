//! Detection of another live process holding this node's S2S identity.
//!
//! Two independent observations produce evidence:
//!
//! * A dial that completes mTLS against a certificate carrying the local node
//!   id. When this process's own acceptor did not see the same TLS connection
//!   (matched by a keying-material exporter both ends derive identically), the
//!   dial did not loop back through a local listener or a NAT hairpin: some
//!   other machine presents this identity.
//! * A peer refusing our session because it already holds a live session for
//!   this node id from an endpoint it knows, while we connect from one it does
//!   not.
//!
//! The first evidence is retained so startup can refuse to join the overlay.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::sync::{Notify, watch};
use tracing::error;

use crate::service_level::TransportKind;
use crate::types::NodeIdentifier;

/// RFC 5705/8446 exporter label binding a self-loop observation to one TLS
/// connection. Both ends of the same connection derive the same value.
pub(crate) const SELF_LOOP_EXPORTER_LABEL: &[u8] = b"EXPORTER-shitspeak-s2s-self-loop";
pub(crate) const SELF_LOOP_EXPORTER_LEN: usize = 32;
pub(crate) type SelfLoopExporter = [u8; SELF_LOOP_EXPORTER_LEN];

/// How long a dialer that reached its own identity waits for this process's
/// acceptor to report the same connection before calling it a duplicate.
pub(crate) const SELF_LOOP_ACCEPT_GRACE: Duration = Duration::from_secs(2);
const SELF_LOOP_RETENTION: Duration = Duration::from_secs(30);
const SELF_LOOP_MAX_ENTRIES: usize = 64;

/// A peer's statement that a node id has a live overlay neighbour, aged so
/// the requester can translate it onto its own clock.
///
/// `not_before` is when the requester started the connection that produced
/// the statement. Since the peer built the statement after that instant, an
/// observation of `hello_age` cannot be older than
/// `not_before - hello_age`. That bound is what makes the statement usable as
/// evidence of a *live* competitor rather than of a departed one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LivenessAttestation {
    pub boot_epoch: u64,
    pub hello_age: Duration,
    pub not_before: Instant,
}

impl LivenessAttestation {
    /// Whether this statement proves the identity was live after `boot_start`.
    ///
    /// `boot_start` is when this process began; a hello older than that can
    /// only belong to an earlier incarnation of this very node.
    pub fn proves_alive_after(&self, boot_start: Instant) -> bool {
        self.not_before
            .saturating_duration_since(boot_start)
            > self.hello_age
    }
}

/// Overlay liveness oracle: `(boot_epoch, hello_age)` when `node` is a live
/// overlay neighbour, `None` otherwise. Installed by the overlay; absent the
/// transport has no basis to call a session a duplicate.
pub type IdentityLivenessOracle =
    Arc<dyn Fn(NodeIdentifier) -> Option<(u64, Duration)> + Send + Sync>;

/// Encode a liveness attestation as the payload of a refusal notice.
pub(crate) fn encode_attestation(attestation: &LivenessAttestation) -> Vec<u8> {
    let mut out = Vec::with_capacity(16);
    out.extend_from_slice(&attestation.boot_epoch.to_le_bytes());
    out.extend_from_slice(&attestation.hello_age.as_micros().min(u64::MAX as u128).to_le_bytes());
    out
}

/// Decode a refusal notice payload. `not_before` is the instant the dial
/// that produced the notice was started.
pub(crate) fn decode_attestation(payload: &[u8], not_before: Instant) -> Option<LivenessAttestation> {
    if payload.len() != 16 {
        return None;
    }
    let boot_epoch = u64::from_le_bytes(payload[0..8].try_into().ok()?);
    let age_us = u64::from_le_bytes(payload[8..16].try_into().ok()?);
    Some(LivenessAttestation {
        boot_epoch,
        hello_age: Duration::from_micros(age_us),
        not_before,
    })
}

/// What proved that another process holds this node's identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DuplicateIdentityEvidenceKind {
    /// A dial reached a remote process presenting this node's certificate.
    RemoteSelfLoop,
    /// A peer refused our session: it holds a live session for this node id
    /// from a known endpoint and we connected from a new one.
    RejectedByPeer,
}

impl DuplicateIdentityEvidenceKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::RemoteSelfLoop => "remote_self_loop",
            Self::RejectedByPeer => "rejected_by_peer",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuplicateIdentityEvidence {
    kind: DuplicateIdentityEvidenceKind,
    transport: TransportKind,
    remote: Option<SocketAddr>,
    reporter: Option<NodeIdentifier>,
    attestation: Option<LivenessAttestation>,
}

impl DuplicateIdentityEvidence {
    pub(crate) fn remote_self_loop(transport: TransportKind, remote: SocketAddr) -> Self {
        Self {
            kind: DuplicateIdentityEvidenceKind::RemoteSelfLoop,
            transport,
            remote: Some(remote),
            reporter: None,
            attestation: None,
        }
    }

    pub(crate) fn rejected_by_peer(
        transport: TransportKind,
        remote: Option<SocketAddr>,
        reporter: NodeIdentifier,
    ) -> Self {
        Self {
            kind: DuplicateIdentityEvidenceKind::RejectedByPeer,
            transport,
            remote,
            reporter: Some(reporter),
            attestation: None,
        }
    }

    /// Attach the peer's liveness statement, when the notice carried one.
    pub fn with_attestation(mut self, attestation: Option<LivenessAttestation>) -> Self {
        self.attestation = attestation;
        self
    }

    /// The peer's liveness statement, if the notice carried one.
    pub fn attestation(&self) -> Option<LivenessAttestation> {
        self.attestation
    }

    /// Whether this evidence proves a competitor was live after `boot_start`.
    ///
    /// Only an attested refusal can: a bare transport rejection or a remote
    /// self-loop says nothing about whether the other process is still up.
    pub fn proves_alive_after(&self, boot_start: Instant) -> bool {
        self.attestation
            .is_some_and(|attestation| attestation.proves_alive_after(boot_start))
    }

    pub fn kind(&self) -> DuplicateIdentityEvidenceKind {
        self.kind
    }

    pub fn transport(&self) -> TransportKind {
        self.transport
    }

    /// Remote socket of the connection that produced the evidence, if known.
    pub fn remote(&self) -> Option<SocketAddr> {
        self.remote
    }

    /// Peer that refused our session, for [`DuplicateIdentityEvidenceKind::RejectedByPeer`].
    pub fn reporter(&self) -> Option<NodeIdentifier> {
        self.reporter
    }
}

/// Holds the first duplicate-identity evidence observed by this manager.
#[derive(Debug)]
pub(crate) struct DuplicateIdentitySignal {
    first: watch::Sender<Option<DuplicateIdentityEvidence>>,
}

impl DuplicateIdentitySignal {
    pub(crate) fn new() -> Self {
        Self {
            first: watch::Sender::new(None),
        }
    }

    pub(crate) fn report(&self, evidence: DuplicateIdentityEvidence) {
        error!(
            kind = evidence.kind().label(),
            transport = ?evidence.transport(),
            remote = ?evidence.remote(),
            reporter = ?evidence.reporter(),
            "another live process holds this node's S2S identity"
        );
        self.first.send_if_modified(|first| {
            if first.is_some() {
                return false;
            }
            *first = Some(evidence);
            true
        });
    }

    pub(crate) fn current(&self) -> Option<DuplicateIdentityEvidence> {
        self.first.borrow().clone()
    }

    pub(crate) fn subscribe(&self) -> watch::Receiver<Option<DuplicateIdentityEvidence>> {
        self.first.subscribe()
    }
}

/// Self-loop TLS connections accepted by this process, keyed by exporter.
#[derive(Debug, Default)]
pub(crate) struct SelfLoopRegistry {
    accepted: Mutex<VecDeque<(Instant, SelfLoopExporter)>>,
    changed: Notify,
}

impl SelfLoopRegistry {
    pub(crate) fn record_accepted(&self, exporter: SelfLoopExporter) {
        {
            let now = Instant::now();
            let mut accepted = self.accepted.lock();
            while accepted
                .front()
                .is_some_and(|(at, _)| now.saturating_duration_since(*at) > SELF_LOOP_RETENTION)
                || accepted.len() >= SELF_LOOP_MAX_ENTRIES
            {
                accepted.pop_front();
            }
            accepted.push_back((now, exporter));
        }
        self.changed.notify_waiters();
    }

    fn take(&self, exporter: &SelfLoopExporter) -> bool {
        let mut accepted = self.accepted.lock();
        match accepted.iter().position(|(_, seen)| seen == exporter) {
            Some(pos) => {
                accepted.remove(pos);
                true
            }
            None => false,
        }
    }

    /// Whether this process's acceptor terminated the same TLS connection
    /// within `grace`.
    pub(crate) async fn accepted_by_this_process(
        &self,
        exporter: &SelfLoopExporter,
        grace: Duration,
    ) -> bool {
        let deadline = tokio::time::Instant::now() + grace;
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.take(exporter) {
                return true;
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                return self.take(exporter);
            }
        }
    }
}

/// Completion tracker for the seed dials issued when the manager starts.
#[derive(Debug, Default)]
pub(crate) struct InitialSeedDials {
    pending: AtomicUsize,
    changed: Notify,
}

impl InitialSeedDials {
    pub(crate) fn begin(&self, count: usize) {
        self.pending.store(count, Ordering::Release);
    }

    pub(crate) fn finish_one(&self) {
        let _ = self
            .pending
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |pending| {
                pending.checked_sub(1)
            });
        self.changed.notify_waiters();
    }

    /// Whether every initial seed dial has finished.
    pub(crate) fn finished(&self) -> bool {
        self.pending.load(Ordering::Acquire) == 0
    }

    /// Wait until every initial seed dial finished. Returns false on timeout.
    pub(crate) async fn wait(&self, timeout: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.pending.load(Ordering::Acquire) == 0 {
                return true;
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                return self.pending.load(Ordering::Acquire) == 0;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn self_loop_registry_matches_exporter_recorded_by_local_acceptor() {
        let registry = SelfLoopRegistry::default();
        let exporter = [7u8; SELF_LOOP_EXPORTER_LEN];
        registry.record_accepted(exporter);

        assert!(
            registry
                .accepted_by_this_process(&exporter, Duration::from_millis(10))
                .await
        );
        // A match is consumed so it cannot vouch for a second connection.
        assert!(
            !registry
                .accepted_by_this_process(&exporter, Duration::from_millis(10))
                .await
        );
    }

    #[tokio::test]
    async fn self_loop_registry_waits_for_late_local_acceptor() {
        let registry = std::sync::Arc::new(SelfLoopRegistry::default());
        let exporter = [9u8; SELF_LOOP_EXPORTER_LEN];
        let recorder = registry.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(30)).await;
            recorder.record_accepted(exporter);
        });

        assert!(
            registry
                .accepted_by_this_process(&exporter, Duration::from_secs(2))
                .await
        );
    }

    #[tokio::test]
    async fn self_loop_registry_rejects_unknown_connection_after_grace() {
        let registry = SelfLoopRegistry::default();
        registry.record_accepted([1u8; SELF_LOOP_EXPORTER_LEN]);

        assert!(
            !registry
                .accepted_by_this_process(&[2u8; SELF_LOOP_EXPORTER_LEN], Duration::from_millis(20))
                .await
        );
    }

    #[test]
    fn duplicate_identity_signal_keeps_first_evidence() {
        let signal = DuplicateIdentitySignal::new();
        let first = DuplicateIdentityEvidence::remote_self_loop(
            TransportKind::Tcp,
            "192.0.2.1:64801".parse().unwrap(),
        );
        signal.report(first.clone());
        signal.report(DuplicateIdentityEvidence::rejected_by_peer(
            TransportKind::Quic,
            None,
            4,
        ));

        assert_eq!(signal.current(), Some(first));
    }

    #[tokio::test]
    async fn initial_seed_dials_wait_for_every_dial() {
        let dials = std::sync::Arc::new(InitialSeedDials::default());
        dials.begin(2);
        assert!(!dials.wait(Duration::from_millis(10)).await);

        let finisher = dials.clone();
        tokio::spawn(async move {
            finisher.finish_one();
            tokio::time::sleep(Duration::from_millis(20)).await;
            finisher.finish_one();
        });
        assert!(dials.wait(Duration::from_secs(2)).await);
    }
}
