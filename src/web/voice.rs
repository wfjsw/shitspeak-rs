use std::collections::{HashMap, VecDeque};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpeakerAssignment {
    pub ssrc: u32,
    pub speaker_session: u32,
    pub epoch: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VoiceEpoch {
    pub epoch: u64,
    pub target: VoiceTargetKind,
    pub ptt: bool,
    pub acknowledged: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VoiceTargetKind {
    Normal,
    ServerLoopback,
    Slot(u32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SsrcAllocationError {
    EmptyPool,
}

#[derive(Debug, Clone)]
pub struct SsrcAllocator {
    free: VecDeque<u32>,
    active: HashMap<u32, u32>,
}

impl SsrcAllocator {
    pub fn new(first_ssrc: u32, capacity: u32) -> Self {
        let free = (first_ssrc..first_ssrc.saturating_add(capacity)).collect();
        Self {
            free,
            active: HashMap::new(),
        }
    }

    pub fn from_ssrcs(ssrcs: impl IntoIterator<Item = u32>) -> Self {
        let mut free = VecDeque::new();
        for ssrc in ssrcs {
            if !free.contains(&ssrc) {
                free.push_back(ssrc);
            }
        }
        Self {
            free,
            active: HashMap::new(),
        }
    }

    pub fn assign(
        &mut self,
        speaker_session: u32,
        epoch: u64,
    ) -> Result<SpeakerAssignment, SsrcAllocationError> {
        if let Some(ssrc) = self.active.get(&speaker_session).copied() {
            return Ok(SpeakerAssignment {
                ssrc,
                speaker_session,
                epoch,
            });
        }

        let Some(ssrc) = self.free.pop_front() else {
            return Err(SsrcAllocationError::EmptyPool);
        };
        self.active.insert(speaker_session, ssrc);
        Ok(SpeakerAssignment {
            ssrc,
            speaker_session,
            epoch,
        })
    }

    pub fn release(&mut self, speaker_session: u32) -> Option<u32> {
        let ssrc = self.active.remove(&speaker_session)?;
        self.free.push_back(ssrc);
        Some(ssrc)
    }

    pub fn active_ssrc(&self, speaker_session: u32) -> Option<u32> {
        self.active.get(&speaker_session).copied()
    }

    pub fn active_len(&self) -> usize {
        self.active.len()
    }
}

#[derive(Debug, Clone)]
pub struct InboundVoiceMetadata {
    latest_epoch: Option<VoiceEpoch>,
}

#[derive(Debug, Clone)]
pub struct RtpFrameNumberMapper {
    next_frame_number: u64,
    active: Option<RtpFrameNumberStream>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RtpFrameNumberStream {
    ssrc: u32,
    epoch: u64,
    base_rtp_timestamp: u32,
    base_frame_number: u64,
    last_rtp_timestamp: u32,
    last_frame_number: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtpFrameNumberMapping {
    pub frame_number: u64,
    pub rtp_timestamp: u32,
}

const OPUS_RTP_CLOCK_HZ: u32 = 48_000;
const OPUS_FRAME_NUMBER_HZ: u32 = 100;
const RTP_TICKS_PER_FRAME_NUMBER: u32 = OPUS_RTP_CLOCK_HZ / OPUS_FRAME_NUMBER_HZ;

impl InboundVoiceMetadata {
    pub fn new() -> Self {
        Self { latest_epoch: None }
    }

    pub fn update_epoch(&mut self, epoch: u64, target: VoiceTargetKind, ptt: bool) -> bool {
        let should_update = self
            .latest_epoch
            .map(|current| epoch > current.epoch)
            .unwrap_or(true);
        if should_update {
            self.latest_epoch = Some(VoiceEpoch {
                epoch,
                target,
                ptt,
                acknowledged: false,
            });
        }
        should_update
    }

    pub fn acknowledge(&mut self, epoch: u64) -> bool {
        let Some(current) = self.latest_epoch.as_mut() else {
            return false;
        };
        if current.epoch != epoch {
            return false;
        }
        current.acknowledged = true;
        true
    }

    pub fn routable_epoch(&self) -> Option<VoiceEpoch> {
        self.latest_epoch.filter(|epoch| epoch.acknowledged)
    }
}

impl Default for InboundVoiceMetadata {
    fn default() -> Self {
        Self::new()
    }
}

impl RtpFrameNumberMapper {
    pub fn new() -> Self {
        Self {
            next_frame_number: 0,
            active: None,
        }
    }

    pub fn map_packet(
        &mut self,
        ssrc: u32,
        epoch: u64,
        rtp_timestamp: u32,
    ) -> RtpFrameNumberMapping {
        let should_start_stream = self
            .active
            .map(|stream| stream.ssrc != ssrc || stream.epoch != epoch)
            .unwrap_or(true);

        if should_start_stream {
            return self.start_stream(ssrc, epoch, rtp_timestamp);
        }

        let Some(stream) = self.active.as_mut() else {
            return self.start_stream(ssrc, epoch, rtp_timestamp);
        };

        let timestamp_delta = rtp_timestamp.wrapping_sub(stream.base_rtp_timestamp);
        let frame_delta = u64::from(timestamp_delta / RTP_TICKS_PER_FRAME_NUMBER);
        let mut frame_number = stream.base_frame_number.saturating_add(frame_delta);
        if frame_number <= stream.last_frame_number {
            frame_number = stream.last_frame_number.saturating_add(1);
        }

        stream.last_rtp_timestamp = rtp_timestamp;
        stream.last_frame_number = frame_number;
        self.next_frame_number = frame_number.saturating_add(1);

        RtpFrameNumberMapping {
            frame_number,
            rtp_timestamp,
        }
    }

    fn start_stream(&mut self, ssrc: u32, epoch: u64, rtp_timestamp: u32) -> RtpFrameNumberMapping {
        let frame_number = self.next_frame_number;
        self.active = Some(RtpFrameNumberStream {
            ssrc,
            epoch,
            base_rtp_timestamp: rtp_timestamp,
            base_frame_number: frame_number,
            last_rtp_timestamp: rtp_timestamp,
            last_frame_number: frame_number,
        });
        self.next_frame_number = frame_number.saturating_add(1);
        RtpFrameNumberMapping {
            frame_number,
            rtp_timestamp,
        }
    }
}

impl Default for RtpFrameNumberMapper {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocator_reuses_existing_speaker_ssrc() {
        let mut allocator = SsrcAllocator::new(10, 2);

        let first = allocator.assign(42, 1).unwrap();
        let second = allocator.assign(42, 2).unwrap();

        assert_eq!(first.ssrc, second.ssrc);
        assert_eq!(allocator.active_len(), 1);
    }

    #[test]
    fn allocator_recycles_released_ssrc() {
        let mut allocator = SsrcAllocator::new(10, 1);
        let first = allocator.assign(1, 1).unwrap();
        assert!(allocator.assign(2, 1).is_err());

        assert_eq!(allocator.release(1), Some(first.ssrc));
        let second = allocator.assign(2, 1).unwrap();
        assert_eq!(second.ssrc, first.ssrc);
    }

    #[test]
    fn allocator_uses_explicit_ssrc_pool() {
        let mut allocator = SsrcAllocator::from_ssrcs([44, 55, 44]);

        assert_eq!(allocator.assign(1, 1).unwrap().ssrc, 44);
        assert_eq!(allocator.assign(2, 1).unwrap().ssrc, 55);
        assert!(allocator.assign(3, 1).is_err());
    }

    #[test]
    fn inbound_epoch_requires_ack_before_routing() {
        let mut metadata = InboundVoiceMetadata::new();
        assert!(metadata.update_epoch(7, VoiceTargetKind::Normal, true));
        assert!(metadata.routable_epoch().is_none());

        assert!(metadata.acknowledge(7));
        assert_eq!(
            metadata.routable_epoch(),
            Some(VoiceEpoch {
                epoch: 7,
                target: VoiceTargetKind::Normal,
                ptt: true,
                acknowledged: true,
            })
        );
    }

    #[test]
    fn inbound_epoch_ignores_stale_updates() {
        let mut metadata = InboundVoiceMetadata::new();
        assert!(metadata.update_epoch(7, VoiceTargetKind::Normal, true));
        assert!(!metadata.update_epoch(6, VoiceTargetKind::Slot(1), true));
        assert!(metadata.acknowledge(7));
        assert_eq!(
            metadata.routable_epoch().unwrap().target,
            VoiceTargetKind::Normal
        );
    }

    #[test]
    fn rtp_mapper_normalizes_random_initial_timestamp() {
        let mut mapper = RtpFrameNumberMapper::new();

        assert_eq!(mapper.map_packet(9, 1, 123_456).frame_number, 0);
        assert_eq!(
            mapper
                .map_packet(9, 1, 123_456 + RTP_TICKS_PER_FRAME_NUMBER)
                .frame_number,
            1
        );
        assert_eq!(
            mapper
                .map_packet(9, 1, 123_456 + (3 * RTP_TICKS_PER_FRAME_NUMBER))
                .frame_number,
            3
        );
    }

    #[test]
    fn rtp_mapper_stays_monotonic_for_small_or_duplicate_timestamp_steps() {
        let mut mapper = RtpFrameNumberMapper::new();

        assert_eq!(mapper.map_packet(9, 1, 10_000).frame_number, 0);
        assert_eq!(mapper.map_packet(9, 1, 10_120).frame_number, 1);
        assert_eq!(mapper.map_packet(9, 1, 10_120).frame_number, 2);
    }

    #[test]
    fn rtp_mapper_handles_u32_timestamp_wrap() {
        let mut mapper = RtpFrameNumberMapper::new();

        assert_eq!(mapper.map_packet(9, 1, u32::MAX - 239).frame_number, 0);
        assert_eq!(mapper.map_packet(9, 1, 240).frame_number, 1);
        assert_eq!(mapper.map_packet(9, 1, 720).frame_number, 2);
    }

    #[test]
    fn rtp_mapper_does_not_reuse_frame_numbers_across_epochs_or_ssrcs() {
        let mut mapper = RtpFrameNumberMapper::new();

        assert_eq!(mapper.map_packet(9, 1, 90_000).frame_number, 0);
        assert_eq!(mapper.map_packet(9, 1, 90_480).frame_number, 1);
        assert_eq!(mapper.map_packet(9, 2, 50).frame_number, 2);
        assert_eq!(mapper.map_packet(10, 2, 50).frame_number, 3);
    }
}
