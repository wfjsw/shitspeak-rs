//! Voice features a node advertises to its peers.
//!
//! Voice keeps one entry under [`VOICE_SERVICE_TAG`] in the opaque
//! upper-layer capability envelope carried by LSAs. Today the entry says
//! whether this node solves sliding-window FEC parity; a sender codes a
//! stream with it only when every recipient advertises it.
//!
//! Voice never creates the envelope. Replication reads a present envelope as
//! authoritative and an absent one through deprecated LSA fields, so an
//! envelope holding only voice's entry would briefly advertise "no
//! replication" for a node whose replication has not published yet. Voice
//! therefore merges into an envelope that already exists and retries until
//! one does.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use prost::Message as _;
use shitspeak_core::NodeIdentifier;
use shitspeak_proto::s2s_application_proto as pb;
use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::application::proto::VOICE_SERVICE_TAG;
use crate::overlay::OverlayNetwork;
use crate::upper_layer_capabilities::{CapabilityEnvelopeError, UpperLayerCapabilityEnvelope};

/// How often the publisher re-merges voice's entry into the local envelope:
/// until the envelope first exists, and afterwards in case another layer
/// rewrote it without voice's entry.
const PUBLISH_INTERVAL: Duration = Duration::from_secs(5);
/// How long a peer's decoded capability is reused before re-reading its LSA.
const PEER_CACHE_TTL: Duration = Duration::from_secs(2);

/// Merge voice's entry into an existing capability envelope. `Ok(None)` when
/// there is no envelope yet: voice never creates one (see the module docs).
/// With `fec_sliding` false the entry is removed, so the envelope carries
/// nothing for voice.
pub(crate) fn merge_voice_capabilities(
    existing: Option<&[u8]>,
    fec_sliding: bool,
) -> Result<Option<Vec<u8>>, CapabilityEnvelopeError> {
    let Some(existing) = existing else {
        return Ok(None);
    };
    let mut envelope = UpperLayerCapabilityEnvelope::decode(existing)?;
    if fec_sliding {
        let capabilities = pb::VoiceCapabilities {
            fec_sliding_v1: true,
        };
        envelope.insert(VOICE_SERVICE_TAG, capabilities.encode_to_vec())?;
    } else {
        envelope.remove(VOICE_SERVICE_TAG);
    }
    envelope.encode().map(Some)
}

/// Whether an advertised envelope says the node solves sliding-window FEC
/// parity. Absent, malformed, or missing entries all read as no.
pub(crate) fn advertises_fec_sliding(envelope: Option<&[u8]>) -> bool {
    let Some(envelope) = envelope.and_then(|src| UpperLayerCapabilityEnvelope::decode(src).ok())
    else {
        return false;
    };
    envelope
        .get(VOICE_SERVICE_TAG)
        .and_then(|payload| pb::VoiceCapabilities::decode(payload).ok())
        .is_some_and(|capabilities| capabilities.fec_sliding_v1)
}

/// Keep voice's entry merged into the local envelope for the life of the
/// voice service.
pub(crate) fn spawn_publisher(
    overlay: OverlayNetwork,
    fec_sliding: bool,
    shutdown: CancellationToken,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(PUBLISH_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = interval.tick() => {}
            }
            // With no envelope yet the merge yields `None` again, which the
            // overlay treats as no change.
            if let Err(error) = overlay.modify_upper_layer_capabilities(|current| {
                merge_voice_capabilities(current, fec_sliding)
            }) {
                warn!(
                    ?error,
                    "refusing to replace malformed local upper-layer capabilities"
                );
            }
        }
    });
}

/// Peer capability reads, cached briefly so a sender does not decode every
/// recipient's envelope for every frame.
#[derive(Debug, Default)]
pub(crate) struct PeerCapabilityCache {
    fec_sliding: Mutex<HashMap<NodeIdentifier, (bool, Instant)>>,
}

impl PeerCapabilityCache {
    /// Whether every node in `dsts` advertises sliding-window FEC parity,
    /// reading an uncached or stale peer through `advertised`.
    pub(crate) fn all_fec_sliding(
        &self,
        dsts: &[NodeIdentifier],
        advertised: impl Fn(NodeIdentifier) -> bool,
    ) -> bool {
        if dsts.is_empty() {
            return false;
        }
        let now = Instant::now();
        let mut cache = self.fec_sliding.lock();
        dsts.iter().all(|&dst| {
            if let Some((capable, read_at)) = cache.get(&dst)
                && now.saturating_duration_since(*read_at) < PEER_CACHE_TTL
            {
                return *capable;
            }
            let capable = advertised(dst);
            cache.insert(dst, (capable, now));
            capable
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::voice::capability::pb::VoiceCapabilities;

    const OTHER_TAG: u32 = 9;

    fn envelope_with_other_entry() -> Vec<u8> {
        let mut envelope = UpperLayerCapabilityEnvelope::new();
        envelope.insert(OTHER_TAG, vec![1, 2, 3]).unwrap();
        envelope.encode().unwrap()
    }

    #[test]
    fn voice_never_creates_the_envelope() {
        assert_eq!(merge_voice_capabilities(None, true).unwrap(), None);
        assert_eq!(merge_voice_capabilities(None, false).unwrap(), None);
    }

    #[test]
    fn merge_preserves_other_entries_and_round_trips() {
        let merged = merge_voice_capabilities(Some(&envelope_with_other_entry()), true)
            .unwrap()
            .unwrap();
        assert!(advertises_fec_sliding(Some(&merged)));
        let decoded = UpperLayerCapabilityEnvelope::decode(&merged).unwrap();
        assert_eq!(decoded.get(OTHER_TAG), Some(&[1, 2, 3][..]));

        let retracted = merge_voice_capabilities(Some(&merged), false)
            .unwrap()
            .unwrap();
        assert!(!advertises_fec_sliding(Some(&retracted)));
        assert_eq!(retracted, envelope_with_other_entry());
    }

    #[test]
    fn absent_malformed_or_false_entries_read_as_not_capable() {
        assert!(!advertises_fec_sliding(None));
        assert!(!advertises_fec_sliding(Some(&[0xff, 0xff, 0xff])));
        assert!(!advertises_fec_sliding(Some(&envelope_with_other_entry())));
        let mut envelope = UpperLayerCapabilityEnvelope::new();
        envelope
            .insert(
                VOICE_SERVICE_TAG,
                VoiceCapabilities {
                    fec_sliding_v1: false,
                }
                .encode_to_vec(),
            )
            .unwrap();
        assert!(!advertises_fec_sliding(Some(&envelope.encode().unwrap())));
        let mut envelope = UpperLayerCapabilityEnvelope::new();
        envelope.insert(VOICE_SERVICE_TAG, vec![0xff]).unwrap();
        assert!(!advertises_fec_sliding(Some(&envelope.encode().unwrap())));
    }

    #[test]
    fn a_merge_into_a_malformed_envelope_is_refused() {
        assert!(merge_voice_capabilities(Some(&[0xff, 0xff, 0xff]), true).is_err());
    }

    #[test]
    fn every_recipient_must_advertise_and_reads_are_cached() {
        let cache = PeerCapabilityCache::default();
        let reads = std::cell::Cell::new(0);
        let advertised = |dst: NodeIdentifier| {
            reads.set(reads.get() + 1);
            dst != 3
        };
        assert!(cache.all_fec_sliding(&[1, 2], advertised));
        assert!(!cache.all_fec_sliding(&[1, 2, 3], advertised));
        assert!(!cache.all_fec_sliding(&[], advertised));
        // 1 and 2 were read once and then served from the cache.
        assert_eq!(reads.get(), 3);
    }
}
