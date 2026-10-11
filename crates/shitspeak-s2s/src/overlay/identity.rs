//! Identity liveness attestation.
//!
//! Two processes can hold one node id. Deciding which one is real needs a
//! statement about **liveness on the overlay**, not merely about a TLS
//! session: a crashed or torn-down incarnation leaves sessions and relayed
//! LSAs behind that prove nothing about who is alive now.
//!
//! [`IdentityProbe`] asks a directly-connected peer what it has observed for
//! one node id. The answer carries only Hello/HelloAck observations, each
//! aged, so the requester can translate it onto its own clock:
//!
//! ```text
//! observation_time >= t_send - age
//! ```
//!
//! where `t_send` is when the requester sent the probe. The responder built
//! its answer after receiving that probe, so the observation it reports is at
//! least that recent. A hello that predates the requester's own start is
//! therefore never evidence of a live competitor — it can only belong to an
//! earlier incarnation of the requester itself.

use std::time::{Duration, Instant};

use bytes::Bytes;
use tracing::{debug, warn};

use shitspeak_core::NodeIdentifier;
use shitspeak_s2s_transport::{ConnectionManager, MessageClass, SendOptions, ServiceLevel};
use shitspeak_proto::s2s_overlay_proto as pb;

use super::duplicate::HelloObservation;
use super::lsdb::{LsaFloor, LinkStateDb};
use super::proto::{OverlayBody, decode_message, encode_message, wrap};

/// One Hello/HelloAck observation reported by a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReportedObservation {
    pub boot_epoch: u64,
    pub age: Duration,
}

/// A peer's answer about one node id's liveness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityProbeResponse {
    pub nonce: u64,
    pub subject: NodeIdentifier,
    pub hello_epochs: Vec<ReportedObservation>,
    pub lsdb_epoch: Option<u64>,
    pub floor_epoch: Option<u64>,
}

impl IdentityProbeResponse {
    /// Whether this answer proves `subject` was alive after `not_before`.
    ///
    /// `t_send` must be the instant the probe was handed to the transport.
    pub fn proves_alive_after(&self, t_send: Instant, not_before: Instant) -> bool {
        // The probe is always sent after we started, so t_send >= not_before
        // and `observation_time > not_before` is `t_send - not_before > age`.
        let since_start = t_send.saturating_duration_since(not_before);
        self.hello_epochs
            .iter()
            .any(|observation| since_start > observation.age)
    }

    /// Live foreign epochs, newest first, as `(boot_epoch, age)`.
    pub fn foreign_epochs(&self, local: u64) -> Vec<(u64, Duration)> {
        let mut out: Vec<(u64, Duration)> = self
            .hello_epochs
            .iter()
            .filter(|observation| observation.boot_epoch != local)
            .map(|observation| (observation.boot_epoch, observation.age))
            .collect();
        out.sort_by_key(|(_, age)| *age);
        out
    }

    /// Decode a response body. Returns `None` for anything else.
    pub fn decode(raw: &[u8]) -> Option<Self> {
        let decoded = decode_message(raw).ok()?;
        match decoded.body? {
            OverlayBody::IdentityProbeResp(resp) => Self::from_probe_resp(resp),
            _ => None,
        }
    }

    /// Decode a raw wire response body.
    pub fn from_probe_resp(resp: pb::IdentityProbeResp) -> Option<Self> {
        let subject = NodeIdentifier::try_from(resp.subject).ok()?;
        let mut hello_epochs = Vec::with_capacity(resp.hello_epochs.len());
        for observation in resp.hello_epochs {
            hello_epochs.push(ReportedObservation {
                boot_epoch: observation.boot_epoch,
                age: Duration::from_micros(observation.age_us),
            });
        }
        Some(Self {
            nonce: resp.nonce,
            subject,
            hello_epochs,
            lsdb_epoch: (resp.lsdb_epoch != 0).then_some(resp.lsdb_epoch),
            floor_epoch: (resp.floor_epoch != 0).then_some(resp.floor_epoch),
        })
    }
}

/// Encode an [`IdentityProbe`] asking about `subject`.
pub fn encode_identity_probe(subject: NodeIdentifier, nonce: u64) -> Option<Bytes> {
    let body = OverlayBody::IdentityProbe(pb::IdentityProbe {
        nonce,
        subject: u32::from(subject),
    });
    encode_message(&wrap(body)).ok()
}

/// Encode an [`IdentityProbeResp`] from local observation state.
pub fn encode_identity_probe_resp(
    subject: NodeIdentifier,
    nonce: u64,
    hello_epochs: &[HelloObservation],
    lsdb: &LinkStateDb,
    floor: &LsaFloor,
) -> Option<Bytes> {
    let lsdb_entry = lsdb.get(subject);
    let floor_entry = floor.get(subject);
    let body = OverlayBody::IdentityProbeResp(pb::IdentityProbeResp {
        nonce,
        subject: u32::from(subject),
        hello_epochs: hello_epochs
            .iter()
            .map(|observation| pb::HelloObservation {
                boot_epoch: observation.boot_epoch,
                age_us: observation.age.as_micros().min(u64::MAX as u128) as u64,
            })
            .collect(),
        lsdb_epoch: lsdb_entry.as_ref().map(|entry| entry.boot_epoch).unwrap_or(0),
        lsdb_seq: lsdb_entry.as_ref().map(|entry| entry.seq).unwrap_or(0),
        floor_epoch: floor_entry.map(|entry| entry.boot_epoch).unwrap_or(0),
        floor_seq: floor_entry.map(|entry| entry.seq).unwrap_or(0),
    });
    encode_message(&wrap(body)).ok()
}

/// Send one probe to `dst`. Returns the instant the send completed, which the
/// caller should use as `t_send` when evaluating the answer.
pub async fn send_identity_probe(
    transport: &ConnectionManager,
    self_id: NodeIdentifier,
    dst: NodeIdentifier,
    subject: NodeIdentifier,
    nonce: u64,
) -> Option<Instant> {
    let payload = encode_identity_probe(subject, nonce)?;
    let packet_kind = crate::debug_io::classify_overlay_body(&OverlayBody::IdentityProbe(
        pb::IdentityProbe {
            nonce,
            subject: u32::from(subject),
        },
    ));
    let payload_len = payload.len();
    match transport
        .try_send_with_options(
            dst,
            ServiceLevel::Reliable,
            None,
            MessageClass::Control,
            payload,
            SendOptions::default().allow_l1_compression(),
        )
        .await
    {
        Ok(()) => {
            crate::debug_io::record_sent(self_id, dst, packet_kind, payload_len);
            Some(Instant::now())
        }
        Err(error) => {
            debug!(peer = dst, %error, "identity probe send failed");
            None
        }
    }
}

/// Tell `dst` that a higher `(boot_epoch, seq)` for `origin` is already
/// known here, so `origin`'s advertisements can never land. Only sent when
/// the LSA arrived directly from the origin itself.
pub async fn send_origin_fenced(
    transport: &ConnectionManager,
    self_id: NodeIdentifier,
    dst: NodeIdentifier,
    origin: NodeIdentifier,
    fence_epoch: u64,
    fence_seq: u64,
) {
    let body = OverlayBody::OriginFenced(pb::OriginFenced {
        origin: u32::from(origin),
        fence_epoch,
        fence_seq,
    });
    let payload = match encode_message(&wrap(body.clone())) {
        Ok(payload) => payload,
        Err(error) => {
            warn!(%error, "origin-fenced encode failed");
            return;
        }
    };
    let packet_kind = crate::debug_io::classify_overlay_body(&body);
    let payload_len = payload.len();
    match transport
        .try_send_with_options(
            dst,
            ServiceLevel::Reliable,
            None,
            MessageClass::Control,
            payload,
            SendOptions::default().allow_l1_compression(),
        )
        .await
    {
        Ok(()) => crate::debug_io::record_sent(self_id, dst, packet_kind, payload_len),
        Err(error) => debug!(peer = dst, %error, "origin-fenced send failed"),
    }
}

/// Reply to an [`IdentityProbe`]. Handled before the duplicate quarantine:
/// a node still in startup preflight may not yet have an overlay identity,
/// and a probe carries no epoch, so answering can never feed a detector.
pub async fn handle_identity_probe(
    lsdb: &LinkStateDb,
    floor: &LsaFloor,
    hello_observations: &[HelloObservation],
    transport: &ConnectionManager,
    self_id: NodeIdentifier,
    sender: NodeIdentifier,
    probe: pb::IdentityProbe,
) {
    let Ok(subject) = NodeIdentifier::try_from(probe.subject) else {
        return;
    };
    let Some(payload) = encode_identity_probe_resp(
        subject,
        probe.nonce,
        hello_observations,
        lsdb,
        floor,
    ) else {
        warn!(peer = sender, "identity probe response encode failed");
        return;
    };
    let body = OverlayBody::IdentityProbeResp(pb::IdentityProbeResp {
        nonce: probe.nonce,
        subject: probe.subject,
        hello_epochs: Vec::new(),
        lsdb_epoch: 0,
        lsdb_seq: 0,
        floor_epoch: 0,
        floor_seq: 0,
    });
    let packet_kind = crate::debug_io::classify_overlay_body(&body);
    let payload_len = payload.len();
    match transport
        .try_send_with_options(
            sender,
            ServiceLevel::Reliable,
            None,
            MessageClass::Control,
            payload,
            SendOptions::default().allow_l1_compression(),
        )
        .await
    {
        Ok(()) => crate::debug_io::record_sent(self_id, sender, packet_kind, payload_len),
        Err(error) => debug!(peer = sender, %error, "identity probe response send failed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation(boot_epoch: u64, age: Duration) -> ReportedObservation {
        ReportedObservation { boot_epoch, age }
    }

    #[test]
    fn observation_is_never_older_than_the_probe_send() {
        let t_send = Instant::now();
        let not_before = t_send;
        let response = IdentityProbeResponse {
            nonce: 1,
            subject: 2,
            hello_epochs: vec![observation(7, Duration::from_secs(5))],
            lsdb_epoch: None,
            floor_epoch: None,
        };
        // The hello is 5s old at the responder, which answered after t_send.
        assert!(!response.proves_alive_after(t_send, not_before));
    }

    #[test]
    fn observation_after_the_requester_started_proves_a_live_competitor() {
        let t_send = Instant::now();
        let not_before = t_send - Duration::from_secs(10);
        let response = IdentityProbeResponse {
            nonce: 1,
            subject: 2,
            hello_epochs: vec![observation(7, Duration::from_millis(500))],
            lsdb_epoch: None,
            floor_epoch: None,
        };
        assert!(response.proves_alive_after(t_send, not_before));
    }

    #[test]
    fn foreign_epochs_exclude_the_local_incarnation() {
        let response = IdentityProbeResponse {
            nonce: 1,
            subject: 2,
            hello_epochs: vec![
                observation(5, Duration::from_secs(1)),
                observation(9, Duration::from_millis(100)),
            ],
            lsdb_epoch: None,
            floor_epoch: None,
        };
        assert_eq!(
            response.foreign_epochs(5),
            vec![(9, Duration::from_millis(100))]
        );
    }

    #[test]
    fn response_round_trips_through_the_wire() {
        let observations = vec![
            HelloObservation {
                boot_epoch: 42,
                age: Duration::from_millis(250),
            },
            HelloObservation {
                boot_epoch: 43,
                age: Duration::from_secs(3),
            },
        ];
        let lsdb = LinkStateDb::new(std::sync::Arc::new(LsaFloor::new(1, None)));
        let floor = LsaFloor::new(1, None);
        let encoded = encode_identity_probe_resp(2, 99, &observations, &lsdb, &floor).unwrap();

        let decoded = IdentityProbeResponse::decode(&encoded).unwrap();
        assert_eq!(decoded.nonce, 99);
        assert_eq!(decoded.subject, 2);
        assert_eq!(
            decoded.hello_epochs,
            vec![
                observation(42, Duration::from_millis(250)),
                observation(43, Duration::from_secs(3)),
            ]
        );
        assert_eq!(decoded.lsdb_epoch, None);
    }
}