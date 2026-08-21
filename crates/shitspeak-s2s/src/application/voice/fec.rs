//! Change-set C3: best-effort block FEC over the datagram voice lane.
//!
//! The sender XORs the last `voice_fec_block_size` equal-length payloads of
//! one speaker into a single parity frame, unicast to each first hop that
//! carried the block. Parity frames are rate-limited per first hop by the
//! overlay's `voice_overlap` lane-headroom budget (capacity ∝ accepted
//! original bytes, i.e. the lane's own load) and only emitted once the
//! first hop's live datagram loss reaches `voice_fec_loss_gate_ppm` — so a
//! healthy lane pays nothing and a lossy lane gets bounded redundancy.
//!
//! A parity block is emitted only when every member payload has the same
//! length: reconstruction is then unambiguous (the recovered payload length
//! is the common member length). A length change discards the partial block
//! rather than send a parity with length ambiguity.
//!
//! The receiver mirrors the last `voice_fec_receiver_window` data frames per
//! `(sender_session, sender_epoch, from)` and retains up to the same number
//! of received parity blocks. When a reorder gap opens (or a parity block
//! arrives), `try_reconstruct` XOR-reconstructs any block member that is
//! missing from the mirror while every sibling is present. Recovered frames
//! enter the reorder as [`crate::application::voice::reorder::VoiceCopyKind::Fec`]
//! and surface as `GapResolution::Fec` in the gap-resolution metric.

use std::collections::{HashMap, HashSet, VecDeque};

use bytes::Bytes;
use shitspeak_core::NodeIdentifier;

use crate::application::proto::VoiceFrame;

/// Whether a FEC parity frame was admitted onto the lane or shed by the
/// first-hop headroom budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FecSendOutcome {
    Sent,
    Shed,
}

/// A completed parity block ready to be encoded onto the wire.
#[derive(Debug, Clone)]
pub(crate) struct FecBlockToSend {
    pub(crate) member_seqs: Vec<u64>,
    pub(crate) parity: Bytes,
    /// Bit `i` set when block member `i` was an utterance terminator.
    pub(crate) terminator_mask: u32,
}

/// XOR of equal-length payloads, zero-padding shorter members to the longest.
/// Blocks are built only from equal-length members, so in practice this is a
/// plain XOR of length == the common member length.
pub(crate) fn xor_payloads(payloads: &[&[u8]]) -> Vec<u8> {
    let max_len = payloads.iter().map(|payload| payload.len()).max().unwrap_or(0);
    let mut acc = vec![0u8; max_len];
    for payload in payloads {
        for (index, byte) in payload.iter().copied().enumerate() {
            acc[index] ^= byte;
        }
    }
    acc
}

/// XOR `payload` into `acc` (bounded to the shorter), returning a new buffer.
fn xor_into(acc: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut out = acc.to_vec();
    let limit = acc.len().min(payload.len());
    for index in 0..limit {
        out[index] ^= payload[index];
    }
    out
}

/// Sender-side ring that turns consecutive sent frames into parity blocks.
#[derive(Debug)]
pub(crate) struct SenderFecWindow {
    block_size: usize,
    pending: Vec<PendingMember>,
}

#[derive(Debug)]
struct PendingMember {
    seq: u64,
    payload: Bytes,
    terminator: bool,
}

impl SenderFecWindow {
    pub(crate) fn new(block_size: usize) -> Self {
        Self { block_size, pending: Vec::new() }
    }

    /// Push the next sent frame. When a full block of equal-length members
    /// completes, returns the parity block to emit and resets the window.
    /// A length change or empty payload discards the partial block (dropped
    /// without emitting).
    pub(crate) fn push(
        &mut self,
        seq: u64,
        payload: Bytes,
        terminator: bool,
    ) -> Option<FecBlockToSend> {
        if self.block_size < 2 || payload.is_empty() {
            self.pending.clear();
            return None;
        }
        if self
            .pending
            .first()
            .is_some_and(|first| first.payload.len() != payload.len())
        {
            // Length changed mid-block: the new frame starts a fresh block.
            self.pending.clear();
        }
        self.pending.push(PendingMember { seq, payload, terminator });
        if self.pending.len() < self.block_size {
            return None;
        }
        let member_seqs = self.pending.iter().map(|member| member.seq).collect();
        let mut terminator_mask = 0u32;
        for (index, member) in self.pending.iter().enumerate() {
            if member.terminator {
                terminator_mask |= 1 << index;
            }
        }
        let payloads: Vec<&[u8]> =
            self.pending.iter().map(|member| member.payload.as_ref()).collect();
        let parity = Bytes::from(xor_payloads(&payloads));
        self.pending.clear();
        Some(FecBlockToSend { member_seqs, parity, terminator_mask })
    }
}

/// A received parity block plus the members the mirror currently holds.
#[derive(Debug)]
struct FecBlock {
    member_seqs: Vec<u64>,
    parity: Bytes,
    terminator_mask: u32,
}

/// Receiver-side mirror of the last `window` data frames for one sender.
#[derive(Debug)]
struct ReceiverFecWindow {
    window: usize,
    received: VecDeque<ReceivedMember>,
    blocks: Vec<FecBlock>,
}

#[derive(Debug)]
struct ReceivedMember {
    seq: u64,
    frame: VoiceFrame,
}

impl ReceiverFecWindow {
    fn new(window: usize) -> Self {
        Self { window: window.max(1), received: VecDeque::new(), blocks: Vec::new() }
    }

    /// Record an inbound data frame (any copy kind). Keeps the most recent
    /// copy of each seq so a replayed original cannot double-count a member.
    fn record_frame(&mut self, frame: VoiceFrame) {
        let seq = frame.s2s_seq;
        self.received.retain(|member| member.seq != seq);
        self.received.push_back(ReceivedMember { seq, frame });
        while self.received.len() > self.window {
            self.received.pop_front();
        }
    }

    fn record_parity(
        &mut self,
        member_seqs: Vec<u64>,
        parity: Bytes,
        terminator_mask: u32,
    ) {
        if member_seqs.len() < 2 {
            return;
        }
        self.blocks.push(FecBlock { member_seqs, parity, terminator_mask });
        while self.blocks.len() > self.window {
            self.blocks.remove(0);
        }
    }

    /// Recover any block member absent from the mirror while every sibling is
    /// present. Only blocks with exactly one absent member are usable (single
    /// parity = single recovery). When `gap` is `Some`, only recover targets
    /// inside that live missing range; `None` recovers anything recoverable.
    /// Returns recovered frames in seq order, deduplicated by seq.
    fn try_reconstruct(&mut self, gap: Option<(u64, u64)>) -> Vec<VoiceFrame> {
        let mut recovered: Vec<VoiceFrame> = Vec::new();
        for block in &self.blocks {
            let present: Vec<&ReceivedMember> = self
                .received
                .iter()
                .filter(|member| block.member_seqs.contains(&member.seq))
                .collect();
            if present.len() != block.member_seqs.len().saturating_sub(1) {
                continue;
            }
            let Some(target) = block
                .member_seqs
                .iter()
                .copied()
                .find(|seq| !present.iter().any(|member| member.seq == *seq))
            else {
                continue;
            };
            if let Some((first, last)) = gap {
                if target < first || target > last {
                    continue;
                }
            }
            let mut acc = xor_into(&block.parity, &[]);
            for member in &present {
                acc = xor_into(&acc, &member.frame.payload);
            }
            // Copy routing metadata from the sibling closest in seq: frames of
            // one utterance share intent, target kind, and server id, and the
            // closest sibling is most likely to be in the same utterance.
            let Some(template) = present.iter().min_by_key(|member| {
                member.seq.abs_diff(target)
            }) else {
                continue;
            };
            let member_index = block
                .member_seqs
                .iter()
                .position(|seq| *seq == target)
                .unwrap_or(0);
            let is_terminator = (block.terminator_mask >> member_index) & 1 == 1;
            recovered.push(VoiceFrame {
                sender_session: template.frame.sender_session,
                server_id: template.frame.server_id.clone(),
                sender_epoch: template.frame.sender_epoch,
                s2s_seq: target,
                target_kind: template.frame.target_kind,
                is_terminator,
                payload: Bytes::from(acc),
                intent: template.frame.intent.clone(),
                proactive_copy: false,
                fec_parity: false,
                fec_member_seqs: Vec::new(),
                fec_terminator_mask: 0,
            });
        }
        recovered.sort_by_key(|frame| frame.s2s_seq);
        let mut seen = HashSet::new();
        recovered.retain(|frame| seen.insert(frame.s2s_seq));
        recovered
    }
}

/// Sender-side FEC state shared by the voice service's send paths. Each
/// `(sender_session, sender_epoch)` gets its own block window, matching the
/// per-session `s2s_seq` space.
#[derive(Debug)]
pub(crate) struct FecSenderState {
    enabled: bool,
    block_size: usize,
    inner: std::sync::Mutex<HashMap<(u32, u64), SenderFecWindow>>,
}

impl FecSenderState {
    pub(crate) fn new(enabled: bool, block_size: usize) -> Self {
        Self {
            enabled,
            block_size,
            inner: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Push a sent frame into the sender window. Returns the completed parity
    /// block when a full equal-length block finishes; otherwise `None`.
    pub(crate) fn push(
        &self,
        sender_session: u32,
        sender_epoch: u64,
        seq: u64,
        payload: Bytes,
        terminator: bool,
    ) -> Option<FecBlockToSend> {
        if !self.enabled {
            return None;
        }
        let mut inner = self.inner.lock().unwrap();
        inner
            .entry((sender_session, sender_epoch))
            .or_insert_with(|| SenderFecWindow::new(self.block_size))
            .push(seq, payload, terminator)
    }
}

/// Per-(sender, epoch, from) receiver FEC state shared with the dispatch task.
#[derive(Debug)]
pub(crate) struct ReceiverFecState {
    inner: std::sync::Mutex<ReceiverFecStateInner>,
}

#[derive(Debug)]
struct ReceiverFecStateInner {
    window: usize,
    /// Eviction cap on the number of live mirrors, a backstop on memory
    /// against an unbounded spread of sender/epoch keys.
    max_mirrors: usize,
    mirrors: Vec<(InstantTrackedKey, ReceiverFecWindow)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct MirrorKey {
    sender_session: u32,
    sender_epoch: u64,
    from: NodeIdentifier,
}

#[derive(Debug, Clone, Copy)]
struct InstantTrackedKey {
    key: MirrorKey,
    last_seen: std::time::Instant,
}

impl ReceiverFecState {
    pub(crate) fn new(window: usize) -> Self {
        Self {
            inner: std::sync::Mutex::new(ReceiverFecStateInner {
                window,
                max_mirrors: 4_096,
                mirrors: Vec::new(),
            }),
        }
    }

    pub(crate) fn record_frame(&self, from: NodeIdentifier, frame: VoiceFrame) {
        let key = MirrorKey {
            sender_session: frame.sender_session,
            sender_epoch: frame.sender_epoch,
            from,
        };
        let mut inner = self.inner.lock().unwrap();
        let mirror = Self::mirror_mut(&mut inner, key);
        mirror.record_frame(frame);
    }

    pub(crate) fn record_parity(
        &self,
        from: NodeIdentifier,
        sender_session: u32,
        sender_epoch: u64,
        member_seqs: Vec<u64>,
        parity: Bytes,
        terminator_mask: u32,
    ) {
        let key = MirrorKey { sender_session, sender_epoch, from };
        let mut inner = self.inner.lock().unwrap();
        let mirror = Self::mirror_mut(&mut inner, key);
        mirror.record_parity(member_seqs, parity, terminator_mask);
    }

    /// Reconstruct block members for this sender, then record the recovered
    /// frames back into the mirror so later blocks can chain off them. `gap`
    /// restricts recovery to the reorder's live missing range; `None` recovers
    /// anything recoverable (parity-arrival trigger).
    pub(crate) fn try_reconstruct(
        &self,
        from: NodeIdentifier,
        sender_session: u32,
        sender_epoch: u64,
        gap: Option<(u64, u64)>,
    ) -> Vec<VoiceFrame> {
        let key = MirrorKey { sender_session, sender_epoch, from };
        let mut inner = self.inner.lock().unwrap();
        let mirror = Self::mirror_mut(&mut inner, key);
        let recovered = mirror.try_reconstruct(gap);
        for frame in &recovered {
            mirror.record_frame(frame.clone());
        }
        recovered
    }

    fn mirror_mut(
        inner: &mut ReceiverFecStateInner,
        key: MirrorKey,
    ) -> &mut ReceiverFecWindow {
        // Index-based so the hit and miss paths never hold two mutable
        // borrows of `inner.mirrors` at once.
        let existing = inner
            .mirrors
            .iter_mut()
            .position(|(tracked, _)| tracked.key == key);
        if let Some(index) = existing {
            inner.mirrors[index].0.last_seen = std::time::Instant::now();
            return &mut inner.mirrors[index].1;
        }
        if inner.mirrors.len() >= inner.max_mirrors {
            // Evict the least-recently-seen mirror as a memory backstop.
            if let Some(index) = inner
                .mirrors
                .iter()
                .enumerate()
                .min_by_key(|(_, (tracked, _))| tracked.last_seen)
                .map(|(index, _)| index)
            {
                inner.mirrors.swap_remove(index);
            }
        }
        let tracked = InstantTrackedKey { key, last_seen: std::time::Instant::now() };
        inner.mirrors.push((tracked, ReceiverFecWindow::new(inner.window)));
        let (_, mirror) = inner.mirrors.last_mut().expect("just pushed");
        mirror
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(seq: u64, payload: &[u8], terminator: bool) -> VoiceFrame {
        VoiceFrame {
            sender_session: 7,
            server_id: shitspeak_core::default_server_id(),
            sender_epoch: 11,
            s2s_seq: seq,
            target_kind: 0,
            is_terminator: terminator,
            payload: Bytes::copy_from_slice(payload),
            intent: None,
            proactive_copy: false,
            fec_parity: false,
            fec_member_seqs: Vec::new(),
            fec_terminator_mask: 0,
        }
    }

    #[test]
    fn sender_emits_parity_only_on_equal_length_blocks() {
        let mut window = SenderFecWindow::new(4);
        // Frames 1-3 buffered, no parity yet.
        for seq in 1..=3 {
            assert!(window.push(seq, Bytes::from_static(b"abcd"), false).is_none());
        }
        // Frame 4 completes the block.
        let block = window.push(4, Bytes::from_static(b"abcd"), false).unwrap();
        assert_eq!(block.member_seqs, vec![1, 2, 3, 4]);
        assert_eq!(block.parity.len(), 4);
        assert_eq!(block.terminator_mask, 0);
    }

    #[test]
    fn sender_discards_block_on_length_change() {
        let mut window = SenderFecWindow::new(4);
        window.push(1, Bytes::from_static(b"abcd"), false);
        window.push(2, Bytes::from_static(b"abcd"), false);
        // A short terminator resets the partial block and starts a fresh one
        // (member 3 joins the new block rather than the discarded one).
        assert!(window.push(3, Bytes::from_static(b"ab"), true).is_none());
        assert!(window.push(4, Bytes::from_static(b"ab"), false).is_none());
        assert!(window.push(5, Bytes::from_static(b"ab"), false).is_none());
        let block = window.push(6, Bytes::from_static(b"ab"), false).unwrap();
        assert_eq!(block.member_seqs, vec![3, 4, 5, 6]);
    }

    #[test]
    fn receiver_reconstructs_a_single_missing_member() {
        let mut mirror = ReceiverFecWindow::new(8);
        mirror.record_frame(frame(1, b"abcd", false));
        mirror.record_frame(frame(2, b"efgh", false));
        mirror.record_frame(frame(3, b"ijkl", false));
        // Block covering seqs 1-4; seq 4 is missing on the wire.
        mirror.record_parity(vec![1, 2, 3, 4], Bytes::from_static(b"QWX\x00"), 0);
        let recovered = mirror.try_reconstruct(Some((4, 4)));
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].s2s_seq, 4);
        // Recovered payload == xor of the three present members and parity.
        // Byte 3: parity `\x00` XORs to identity, so it equals `d ^ h ^ l`.
        let expected = [
            b'Q' ^ b'a' ^ b'e' ^ b'i',
            b'W' ^ b'b' ^ b'f' ^ b'j',
            b'X' ^ b'c' ^ b'g' ^ b'k',
            b'd' ^ b'h' ^ b'l',
        ];
        assert_eq!(recovered[0].payload.as_ref(), expected.as_slice());
    }

    #[test]
    fn receiver_skips_blocks_with_two_missing_members() {
        let mut mirror = ReceiverFecWindow::new(8);
        mirror.record_frame(frame(1, b"abcd", false));
        // seqs 2 and 4 both missing; single parity cannot recover both.
        mirror.record_parity(vec![1, 2, 3, 4], Bytes::from_static(b"zzzz"), 0);
        assert!(mirror.try_reconstruct(None).is_empty());
    }

    #[test]
    fn receiver_restores_terminator_flag() {
        let mut mirror = ReceiverFecWindow::new(8);
        mirror.record_frame(frame(1, b"abcd", false));
        mirror.record_frame(frame(2, b"efgh", false));
        mirror.record_frame(frame(3, b"ijkl", false));
        // Member 4 (index 3) was a terminator.
        mirror.record_parity(vec![1, 2, 3, 4], Bytes::from_static(b"QWX\x00"), 1 << 3);
        let recovered = mirror.try_reconstruct(None);
        assert_eq!(recovered.len(), 1);
        assert!(recovered[0].is_terminator);
    }
}
