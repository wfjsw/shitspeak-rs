//! Codec for the opaque upper-layer capability envelope carried by LSAs.
//!
//! The overlay does not import this module: it stores and floods the encoded
//! protobuf byte-for-byte. Upper layers key entries by the same stable
//! service tag used by `OverlayData` and own their entry payload schemas.

use std::collections::BTreeMap;
use std::fmt;

use prost::Message as _;
use shitspeak_proto::s2s_upper_layer_proto as pb;

const FORMAT_VERSION: u32 = 1;
const MAX_ENTRIES: usize = 32;
pub(crate) const MAX_ENVELOPE_BYTES: usize = 4 * 1024;
const MAX_ENTRY_BYTES: usize = 2 * 1024;

/// A deterministic collection of opaque capabilities keyed by upper-layer
/// service tag.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct UpperLayerCapabilityEnvelope {
    entries: BTreeMap<u32, Vec<u8>>,
}

impl UpperLayerCapabilityEnvelope {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Decode and validate one authoritative capability envelope.
    ///
    /// Entries must be in strictly increasing service-tag order. Protobuf
    /// itself permits duplicate or reordered repeated values, but accepting
    /// those would give one service multiple authorities and make the wire
    /// representation non-deterministic.
    pub(crate) fn decode(src: &[u8]) -> Result<Self, CapabilityEnvelopeError> {
        if src.len() > MAX_ENVELOPE_BYTES {
            return Err(CapabilityEnvelopeError::EnvelopeTooLarge);
        }
        let envelope = pb::UpperLayerCapabilityEnvelope::decode(src)
            .map_err(|_| CapabilityEnvelopeError::MalformedProtobuf)?;
        if envelope.format_version != FORMAT_VERSION {
            return Err(CapabilityEnvelopeError::UnsupportedVersion(
                envelope.format_version,
            ));
        }
        if envelope.entries.len() > MAX_ENTRIES {
            return Err(CapabilityEnvelopeError::TooManyEntries);
        }

        let mut entries = BTreeMap::new();
        let mut previous_tag = None;
        for entry in envelope.entries {
            if entry.service_tag == 0 {
                return Err(CapabilityEnvelopeError::InvalidServiceTag);
            }
            if previous_tag.is_some_and(|previous| entry.service_tag <= previous) {
                return Err(CapabilityEnvelopeError::NonCanonicalServiceTags);
            }
            if entry.payload.len() > MAX_ENTRY_BYTES {
                return Err(CapabilityEnvelopeError::EntryTooLarge);
            }
            previous_tag = Some(entry.service_tag);
            entries.insert(entry.service_tag, entry.payload.to_vec());
        }
        Ok(Self { entries })
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, CapabilityEnvelopeError> {
        if self.entries.len() > MAX_ENTRIES {
            return Err(CapabilityEnvelopeError::TooManyEntries);
        }
        let entries = self
            .entries
            .iter()
            .map(|(service_tag, payload)| {
                if *service_tag == 0 {
                    return Err(CapabilityEnvelopeError::InvalidServiceTag);
                }
                if payload.len() > MAX_ENTRY_BYTES {
                    return Err(CapabilityEnvelopeError::EntryTooLarge);
                }
                Ok(pb::UpperLayerCapabilityEntry {
                    service_tag: *service_tag,
                    payload: payload.clone().into(),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let envelope = pb::UpperLayerCapabilityEnvelope {
            format_version: FORMAT_VERSION,
            entries,
        };
        if envelope.encoded_len() > MAX_ENVELOPE_BYTES {
            return Err(CapabilityEnvelopeError::EnvelopeTooLarge);
        }
        Ok(envelope.encode_to_vec())
    }

    pub(crate) fn get(&self, service_tag: u32) -> Option<&[u8]> {
        self.entries.get(&service_tag).map(Vec::as_slice)
    }

    pub(crate) fn insert(
        &mut self,
        service_tag: u32,
        payload: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, CapabilityEnvelopeError> {
        if service_tag == 0 {
            return Err(CapabilityEnvelopeError::InvalidServiceTag);
        }
        if payload.len() > MAX_ENTRY_BYTES {
            return Err(CapabilityEnvelopeError::EntryTooLarge);
        }
        if !self.entries.contains_key(&service_tag) && self.entries.len() >= MAX_ENTRIES {
            return Err(CapabilityEnvelopeError::TooManyEntries);
        }
        Ok(self.entries.insert(service_tag, payload))
    }

    pub(crate) fn remove(&mut self, service_tag: u32) -> Option<Vec<u8>> {
        self.entries.remove(&service_tag)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CapabilityEnvelopeError {
    MalformedProtobuf,
    UnsupportedVersion(u32),
    InvalidServiceTag,
    NonCanonicalServiceTags,
    TooManyEntries,
    EntryTooLarge,
    EnvelopeTooLarge,
}

impl fmt::Display for CapabilityEnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedProtobuf => f.write_str("upper-layer capability envelope is malformed"),
            Self::UnsupportedVersion(version) => {
                write!(
                    f,
                    "unsupported upper-layer capability envelope version {version}"
                )
            }
            Self::InvalidServiceTag => f.write_str("upper-layer capability service tag is zero"),
            Self::NonCanonicalServiceTags => {
                f.write_str("upper-layer capability service tags are duplicate or out of order")
            }
            Self::TooManyEntries => f.write_str("too many upper-layer capability entries"),
            Self::EntryTooLarge => f.write_str("upper-layer capability entry is too large"),
            Self::EnvelopeTooLarge => f.write_str("upper-layer capability envelope is too large"),
        }
    }
}

impl std::error::Error for CapabilityEnvelopeError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_is_deterministic_and_roundtrips_unknown_services() {
        let mut first = UpperLayerCapabilityEnvelope::new();
        first.insert(9, vec![9]).unwrap();
        first.insert(1, vec![1, 2]).unwrap();

        let mut second = UpperLayerCapabilityEnvelope::new();
        second.insert(1, vec![1, 2]).unwrap();
        second.insert(9, vec![9]).unwrap();

        let encoded = first.encode().unwrap();
        assert_eq!(encoded, second.encode().unwrap());
        let decoded = UpperLayerCapabilityEnvelope::decode(&encoded).unwrap();
        assert_eq!(decoded.get(1), Some(&[1, 2][..]));
        assert_eq!(decoded.get(9), Some(&[9][..]));
    }

    #[test]
    fn present_empty_envelope_is_malformed() {
        assert_eq!(
            UpperLayerCapabilityEnvelope::decode(&[]),
            Err(CapabilityEnvelopeError::UnsupportedVersion(0))
        );
    }

    #[test]
    fn duplicate_or_unsorted_service_tags_are_rejected() {
        let encoded = pb::UpperLayerCapabilityEnvelope {
            format_version: FORMAT_VERSION,
            entries: vec![
                pb::UpperLayerCapabilityEntry {
                    service_tag: 1,
                    payload: vec![1].into(),
                },
                pb::UpperLayerCapabilityEntry {
                    service_tag: 1,
                    payload: vec![2].into(),
                },
            ],
        }
        .encode_to_vec();
        assert_eq!(
            UpperLayerCapabilityEnvelope::decode(&encoded),
            Err(CapabilityEnvelopeError::NonCanonicalServiceTags)
        );
    }

    #[test]
    fn unknown_envelope_version_is_rejected() {
        let encoded = pb::UpperLayerCapabilityEnvelope {
            format_version: FORMAT_VERSION + 1,
            entries: Vec::new(),
        }
        .encode_to_vec();
        assert_eq!(
            UpperLayerCapabilityEnvelope::decode(&encoded),
            Err(CapabilityEnvelopeError::UnsupportedVersion(
                FORMAT_VERSION + 1
            ))
        );
    }
}
