//! Replication-owned capability codec and strict protocol policy.
//!
//! The overlay publishes opaque capability bytes and raw membership facts.
//! This module alone decodes replication's service-tag entry and decides
//! which members participate in strict negotiation. Overlay frame forwarding
//! is opaque and therefore is not modeled as a strict-replication capability.

use std::fmt;

use prost::Message as _;
use shitspeak_core::NodeIdentifier;
use shitspeak_proto::s2s_replication_proto as pb;

use super::proto::REPLICATION_SERVICE_TAG;
use crate::upper_layer_capabilities::{CapabilityEnvelopeError, UpperLayerCapabilityEnvelope};

const REPLICATION_CAPABILITIES_FORMAT_VERSION: u32 = 1;
/// Frozen-target proposals and durable terminal decisions.
pub(crate) const STRICT_PROTOCOL_VERSION_V2: u32 = 2;
/// Pairwise correlated probes and terminal delta synchronization.
pub(crate) const STRICT_PROTOCOL_VERSION_V3: u32 = 3;
/// Maximum strict participant capability advertised by this binary.
pub(crate) const STRICT_PROTOCOL_VERSION_CURRENT: u32 = STRICT_PROTOCOL_VERSION_V3;

/// Replication service participation advertised by one upper-layer endpoint.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ReplicationProtocolCapabilities {
    strict_enabled: bool,
    content_enabled: bool,
    owner_enabled: bool,
    strict_participant_protocol_version: u32,
}

impl ReplicationProtocolCapabilities {
    pub(crate) fn new(
        strict_enabled: bool,
        content_enabled: bool,
        owner_enabled: bool,
        strict_participant_protocol_version: u32,
    ) -> Self {
        Self {
            strict_enabled,
            content_enabled,
            owner_enabled,
            strict_participant_protocol_version,
        }
    }

    pub(crate) fn strict_enabled(self) -> bool {
        self.strict_enabled
    }

    pub(crate) fn content_enabled(self) -> bool {
        self.content_enabled
    }

    pub(crate) fn owner_enabled(self) -> bool {
        self.owner_enabled
    }

    pub(crate) fn strict_participant_protocol_version(self) -> u32 {
        self.strict_participant_protocol_version
    }

    fn is_disabled(self) -> bool {
        !self.strict_enabled && !self.content_enabled && !self.owner_enabled
    }

    fn to_pb(self) -> pb::ReplicationCapabilities {
        pb::ReplicationCapabilities {
            format_version: REPLICATION_CAPABILITIES_FORMAT_VERSION,
            strict_enabled: self.strict_enabled,
            content_enabled: self.content_enabled,
            owner_enabled: self.owner_enabled,
            strict_participant_protocol_version: self.strict_participant_protocol_version,
        }
    }

    fn from_pb(value: pb::ReplicationCapabilities) -> Result<Self, ReplicationCapabilityError> {
        if value.format_version != REPLICATION_CAPABILITIES_FORMAT_VERSION {
            return Err(ReplicationCapabilityError::UnsupportedReplicationVersion(
                value.format_version,
            ));
        }
        if !value.strict_enabled && value.strict_participant_protocol_version != 0 {
            return Err(ReplicationCapabilityError::DisabledStrictHasVersion);
        }
        Ok(Self::new(
            value.strict_enabled,
            value.content_enabled,
            value.owner_enabled,
            value.strict_participant_protocol_version,
        ))
    }
}

/// Encode replication's authoritative entry in a fresh generic envelope.
/// A node with every replication mode disabled emits a valid empty envelope,
/// proving support for the generic format without advertising a
/// replication-specific forwarding capability.
pub(crate) fn encode_upper_layer_capabilities(
    capabilities: ReplicationProtocolCapabilities,
) -> Result<Vec<u8>, CapabilityEnvelopeError> {
    merge_upper_layer_capabilities(None, capabilities)
}

/// Upsert replication's entry while preserving every other upper layer's
/// opaque bytes. A malformed existing local envelope is rejected instead of
/// being silently replaced, because replacement would erase another
/// service's authoritative advertisement.
pub(crate) fn merge_upper_layer_capabilities(
    existing: Option<&[u8]>,
    capabilities: ReplicationProtocolCapabilities,
) -> Result<Vec<u8>, CapabilityEnvelopeError> {
    let mut envelope = match existing {
        Some(existing) => UpperLayerCapabilityEnvelope::decode(existing)?,
        None => UpperLayerCapabilityEnvelope::new(),
    };
    if !capabilities.is_disabled() {
        envelope.insert(
            REPLICATION_SERVICE_TAG,
            capabilities.to_pb().encode_to_vec(),
        )?;
    } else {
        envelope.remove(REPLICATION_SERVICE_TAG);
    }
    envelope.encode()
}

/// Decode an advertised capability set with rolling-upgrade fallback.
///
/// An absent opaque field is a legacy LSA and may use the deprecated service
/// bits and participant version. Any present field is authoritative: invalid
/// protobuf, unsupported formats, duplicate entries, a missing replication
/// entry, or an invalid replication payload all fail closed to no replication
/// support and never consult legacy fields.
pub(crate) fn advertised_replication_capabilities(
    upper_layer_capabilities: Option<&[u8]>,
    legacy_strict_enabled: bool,
    legacy_content_enabled: bool,
    legacy_owner_enabled: bool,
    legacy_strict_participant_protocol_version: u32,
) -> ReplicationProtocolCapabilities {
    let Some(src) = upper_layer_capabilities else {
        return ReplicationProtocolCapabilities::new(
            legacy_strict_enabled,
            legacy_content_enabled,
            legacy_owner_enabled,
            legacy_strict_participant_protocol_version,
        );
    };
    decode_authoritative_replication_capabilities(src).unwrap_or_default()
}

fn decode_authoritative_replication_capabilities(
    src: &[u8],
) -> Result<ReplicationProtocolCapabilities, ReplicationCapabilityError> {
    let envelope =
        UpperLayerCapabilityEnvelope::decode(src).map_err(ReplicationCapabilityError::Envelope)?;
    let Some(payload) = envelope.get(REPLICATION_SERVICE_TAG) else {
        return Ok(ReplicationProtocolCapabilities::default());
    };
    let capabilities = pb::ReplicationCapabilities::decode(payload)
        .map_err(|_| ReplicationCapabilityError::MalformedReplicationPayload)?;
    ReplicationProtocolCapabilities::from_pb(capabilities)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReplicationCapabilityError {
    Envelope(CapabilityEnvelopeError),
    MalformedReplicationPayload,
    UnsupportedReplicationVersion(u32),
    DisabledStrictHasVersion,
}

impl fmt::Display for ReplicationCapabilityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Envelope(error) => error.fmt(f),
            Self::MalformedReplicationPayload => {
                f.write_str("replication capability payload is malformed")
            }
            Self::UnsupportedReplicationVersion(version) => {
                write!(f, "unsupported replication capability version {version}")
            }
            Self::DisabledStrictHasVersion => {
                f.write_str("disabled strict replication advertised a participant version")
            }
        }
    }
}

impl std::error::Error for ReplicationCapabilityError {}

/// One member's capabilities as consumed by strict-replication negotiation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProtocolMember {
    node: NodeIdentifier,
    boot_epoch: u64,
    reachable: bool,
    strict_participant: bool,
    participant_version: u32,
}

impl ProtocolMember {
    pub(crate) fn new(
        node: NodeIdentifier,
        boot_epoch: u64,
        reachable: bool,
        strict_participant: bool,
        participant_version: u32,
    ) -> Self {
        Self {
            node,
            boot_epoch,
            reachable,
            strict_participant,
            participant_version,
        }
    }

    pub(crate) fn node(self) -> NodeIdentifier {
        self.node
    }

    pub(crate) fn boot_epoch(self) -> u64 {
        self.boot_epoch
    }

    pub(crate) fn reachable(self) -> bool {
        self.reachable
    }

    pub(crate) fn strict_participant(self) -> bool {
        self.strict_participant
    }

    pub(crate) fn participant_version(self) -> u32 {
        self.participant_version
    }
}

/// A target incarnation for one strict replication round.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StrictProtocolTarget {
    pub(crate) node: NodeIdentifier,
    pub(crate) boot_epoch: u64,
}

/// Negotiated protocol floor and strict-participant target set captured from
/// one membership view.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StrictProtocolSnapshot {
    pub(crate) negotiated_version: u32,
    pub(crate) targets: Vec<StrictProtocolTarget>,
}

/// Compute the strict participant floor and target set from one immutable
/// member view. Nonparticipants never enter either calculation, regardless
/// of whether they forward opaque overlay data.
pub(crate) fn strict_protocol_snapshot(
    members: impl IntoIterator<Item = ProtocolMember>,
    local_participant_version: Option<u32>,
) -> StrictProtocolSnapshot {
    let members: Vec<ProtocolMember> = members.into_iter().collect();
    let negotiated_version = strict_protocol_floor(&members, local_participant_version);

    let mut targets: Vec<_> = members
        .iter()
        .copied()
        .filter(|member| member.reachable() && member.strict_participant())
        .map(|member| StrictProtocolTarget {
            node: member.node(),
            boot_epoch: member.boot_epoch(),
        })
        .collect();
    targets.sort_by_key(|target| target.node);

    StrictProtocolSnapshot {
        negotiated_version,
        targets,
    }
}

pub(crate) fn strict_protocol_floor(members: &[ProtocolMember], local_version: Option<u32>) -> u32 {
    let mut floor = local_version.unwrap_or(u32::MAX);
    let mut found = local_version.is_some();
    for member in members.iter().copied() {
        if member.reachable() && member.strict_participant() {
            found = true;
            floor = floor.min(member.participant_version());
        }
    }
    if found { floor } else { 0 }
}

/// Count reachable strict participants below the required cumulative
/// protocol version. Nonparticipants are not replication blockers.
pub(crate) fn unsupported_protocol_peers(
    members: impl IntoIterator<Item = ProtocolMember>,
    required_version: u32,
) -> usize {
    members
        .into_iter()
        .filter(|member| member.reachable())
        .filter(|member| member.strict_participant())
        .filter(|member| member.participant_version() < required_version)
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use shitspeak_proto::s2s_upper_layer_proto as upper_pb;

    fn member(node: NodeIdentifier, strict: bool, participant: u32) -> ProtocolMember {
        ProtocolMember::new(node, 1, true, strict, participant)
    }

    fn capabilities(
        strict: bool,
        content: bool,
        owner: bool,
        version: u32,
    ) -> ReplicationProtocolCapabilities {
        ReplicationProtocolCapabilities::new(strict, content, owner, version)
    }

    #[test]
    fn current_participant_capability_does_not_change_v2_proposal_version() {
        assert_eq!(STRICT_PROTOCOL_VERSION_V2, 2);
        assert_eq!(STRICT_PROTOCOL_VERSION_V3, 3);
        assert_eq!(STRICT_PROTOCOL_VERSION_CURRENT, STRICT_PROTOCOL_VERSION_V3);
    }

    #[test]
    fn capability_envelope_roundtrips_replication_services() {
        let expected = capabilities(true, true, false, 2);
        let encoded = encode_upper_layer_capabilities(expected).unwrap();
        assert_eq!(
            advertised_replication_capabilities(Some(&encoded), false, false, false, 0),
            expected
        );
    }

    #[test]
    fn capability_update_preserves_other_service_entries() {
        let mut existing = UpperLayerCapabilityEnvelope::new();
        existing.insert(9, vec![9, 8, 7]).unwrap();
        let existing = existing.encode().unwrap();

        let encoded =
            merge_upper_layer_capabilities(Some(&existing), capabilities(true, false, false, 2))
                .unwrap();
        let decoded = UpperLayerCapabilityEnvelope::decode(&encoded).unwrap();
        assert_eq!(decoded.get(9), Some(&[9, 8, 7][..]));
        assert!(decoded.get(REPLICATION_SERVICE_TAG).is_some());

        let encoded =
            merge_upper_layer_capabilities(Some(&encoded), capabilities(false, false, false, 0))
                .unwrap();
        let decoded = UpperLayerCapabilityEnvelope::decode(&encoded).unwrap();
        assert_eq!(decoded.get(9), Some(&[9, 8, 7][..]));
        assert_eq!(decoded.get(REPLICATION_SERVICE_TAG), None);
    }

    #[test]
    fn disabled_replication_emits_valid_empty_generic_envelope() {
        let encoded =
            encode_upper_layer_capabilities(capabilities(false, false, false, 0)).unwrap();
        let envelope = UpperLayerCapabilityEnvelope::decode(&encoded).unwrap();
        assert_eq!(envelope.get(REPLICATION_SERVICE_TAG), None);
        assert_eq!(
            advertised_replication_capabilities(Some(&encoded), true, true, true, 2),
            ReplicationProtocolCapabilities::default()
        );
    }

    #[test]
    fn absent_envelope_uses_legacy_capabilities() {
        assert_eq!(
            advertised_replication_capabilities(None, true, true, false, 2),
            capabilities(true, true, false, 2)
        );
    }

    #[test]
    fn present_empty_or_malformed_envelope_fails_closed_without_legacy_fallback() {
        for encoded in [Vec::new(), vec![0xff]] {
            assert_eq!(
                advertised_replication_capabilities(Some(&encoded), true, true, true, 2),
                ReplicationProtocolCapabilities::default()
            );
        }
    }

    #[test]
    fn duplicate_replication_entries_fail_closed() {
        let payload = capabilities(true, true, true, 2).to_pb().encode_to_vec();
        let encoded = upper_pb::UpperLayerCapabilityEnvelope {
            format_version: 1,
            entries: vec![
                upper_pb::UpperLayerCapabilityEntry {
                    service_tag: REPLICATION_SERVICE_TAG,
                    payload: payload.clone().into(),
                },
                upper_pb::UpperLayerCapabilityEntry {
                    service_tag: REPLICATION_SERVICE_TAG,
                    payload: payload.into(),
                },
            ],
        }
        .encode_to_vec();
        assert_eq!(
            advertised_replication_capabilities(Some(&encoded), true, true, true, 2),
            ReplicationProtocolCapabilities::default()
        );
    }

    #[test]
    fn disabled_strict_with_nonzero_version_fails_closed() {
        let mut envelope = UpperLayerCapabilityEnvelope::new();
        envelope
            .insert(
                REPLICATION_SERVICE_TAG,
                capabilities(false, true, false, 2).to_pb().encode_to_vec(),
            )
            .unwrap();
        let encoded = envelope.encode().unwrap();
        assert_eq!(
            advertised_replication_capabilities(Some(&encoded), true, true, true, 2),
            ReplicationProtocolCapabilities::default()
        );
    }

    #[test]
    fn nonparticipant_forwarder_does_not_lower_strict_floor_or_join_targets() {
        let snapshot = strict_protocol_snapshot([member(1, true, 2), member(2, false, 0)], Some(2));
        assert_eq!(snapshot.negotiated_version, 2);
        assert_eq!(
            snapshot.targets,
            [StrictProtocolTarget {
                node: 1,
                boot_epoch: 1
            }]
        );
    }

    #[test]
    fn old_participant_lowers_floor() {
        assert_eq!(
            strict_protocol_floor(&[member(1, true, 2), member(2, true, 0)], Some(2)),
            0
        );
    }

    #[test]
    fn no_strict_participants_fails_closed() {
        let snapshot = strict_protocol_snapshot([member(2, false, 0)], None);
        assert_eq!(snapshot.negotiated_version, 0);
        assert!(snapshot.targets.is_empty());
    }

    #[test]
    fn unsupported_diagnostics_ignore_nonparticipants() {
        assert_eq!(
            unsupported_protocol_peers(
                [member(1, true, 1), member(2, false, 0), member(3, true, 2)],
                2
            ),
            1
        );
    }
}
