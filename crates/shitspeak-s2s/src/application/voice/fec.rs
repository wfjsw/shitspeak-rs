//! Change-set C3: best-effort block FEC over the datagram voice lane.
//!
//! The sender combines the last `voice_fec_block_size` equal-length payloads
//! of one speaker into one or two parity frames, unicast to each first hop
//! that carried the block: parity index 0 is a plain XOR sum, and with
//! `voice_fec_parity_blocks = 2` a second GF(2^8)-weighted sum (Vandermonde
//! coefficient 2^member_index) that together with the first recovers two
//! missing members. Parity frames are rate-limited per first hop by the
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
//! arrives), `try_reconstruct` recovers any block member that is missing from
//! the mirror: one missing member needs the XOR parity, two need both parity
//! indices (a GF(2^8) solve). Recovered frames enter the reorder as
//! [`crate::application::voice::reorder::VoiceCopyKind::Fec`] and surface as
//! `GapResolution::Fec` in the gap-resolution metric.

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
    /// Parity index 0: plain XOR of all members. Recovers one missing member.
    pub(crate) parity: Bytes,
    /// Parity index 1: GF(2^8) weighted XOR (coefficient 2^member_index).
    /// Together with `parity` it recovers two missing members. `Some` only
    /// when the sender is configured for two parity frames per block.
    pub(crate) parity2: Option<Bytes>,
    /// Bit `i` set when block member `i` was an utterance terminator.
    pub(crate) terminator_mask: u32,
}

/// XOR of equal-length payloads, zero-padding shorter members to the longest.
/// Blocks are built only from equal-length members, so in practice this is a
/// plain XOR of length == the common member length.
pub(crate) fn xor_payloads(payloads: &[&[u8]]) -> Vec<u8> {
    let max_len = payloads
        .iter()
        .map(|payload| payload.len())
        .max()
        .unwrap_or(0);
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

/// GF(2^8) multiplication over the reducing polynomial x^8 + x^4 + x^3 + x + 1
/// (0x11b). 2 is a primitive element, so the Vandermonde coefficients `2^i`
/// are pairwise distinct for every member index this code uses — which is what
/// lets the weighted parity combine with the plain XOR sum to recover a second
/// missing member.
pub(crate) fn gf_mul(a: u8, b: u8) -> u8 {
    let mut acc = 0u8;
    let mut x = a;
    let mut y = b;
    for _ in 0..8 {
        if y & 1 != 0 {
            acc ^= x;
        }
        if x & 0x80 != 0 {
            x = (x << 1) ^ 0x1b;
        } else {
            x <<= 1;
        }
        y >>= 1;
    }
    acc
}

/// `2^exp` in GF(2^8): the Vandermonde weight for block member `exp`.
pub(crate) fn gf_pow2(exp: u8) -> u8 {
    gf_pow(2, exp)
}

/// `base^exp` in GF(2^8) by square-and-multiply.
fn gf_pow(mut base: u8, mut exp: u8) -> u8 {
    let mut acc = 1u8;
    while exp > 0 {
        if exp & 1 != 0 {
            acc = gf_mul(acc, base);
        }
        base = gf_mul(base, base);
        exp >>= 1;
    }
    acc
}

/// Multiplicative inverse `a^-1 = a^254` in GF(2^8)* (the group has order 255).
fn gf_inv(a: u8) -> u8 {
    debug_assert!(a != 0);
    gf_pow(a, 254)
}

/// Sender-side ring that turns consecutive sent frames into parity blocks.
#[derive(Debug)]
pub(crate) struct SenderFecWindow {
    block_size: usize,
    parity_blocks: usize,
    pending: Vec<PendingMember>,
}

#[derive(Debug)]
struct PendingMember {
    seq: u64,
    payload: Bytes,
    terminator: bool,
}

impl SenderFecWindow {
    pub(crate) fn new(block_size: usize, parity_blocks: usize) -> Self {
        Self {
            block_size,
            parity_blocks: parity_blocks.min(2),
            pending: Vec::new(),
        }
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
        self.pending.push(PendingMember {
            seq,
            payload,
            terminator,
        });
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
        let payloads: Vec<&[u8]> = self
            .pending
            .iter()
            .map(|member| member.payload.as_ref())
            .collect();
        let parity = Bytes::from(xor_payloads(&payloads));
        // Second parity (index 1): GF(2^8) weighted XOR with Vandermonde
        // coefficient 2^member_index, same member length as the XOR sum.
        let parity2 = (self.parity_blocks >= 2).then(|| {
            let mut acc = vec![0u8; parity.len()];
            for (index, payload) in payloads.iter().enumerate() {
                let coefficient = gf_pow2(index as u8);
                for (byte, &value) in payload.iter().enumerate() {
                    acc[byte] ^= gf_mul(coefficient, value);
                }
            }
            Bytes::from(acc)
        });
        self.pending.clear();
        Some(FecBlockToSend {
            member_seqs,
            parity,
            parity2,
            terminator_mask,
        })
    }
}

/// A received parity block plus the members the mirror currently holds.
#[derive(Debug)]
struct FecBlock {
    member_seqs: Vec<u64>,
    /// One slot per parity index; `Some` when that parity frame arrived.
    /// Index 0 is the XOR sum, index 1 the GF(2^8) weighted sum; together
    /// they recover two missing members.
    parities: Vec<Option<Bytes>>,
    terminator_mask: u32,
}

impl FecBlock {
    fn parity(&self, index: usize) -> Option<&[u8]> {
        self.parities
            .get(index)
            .and_then(Option::as_ref)
            .map(Bytes::as_ref)
    }
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
        Self {
            window: window.max(1),
            received: VecDeque::new(),
            blocks: Vec::new(),
        }
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
        parity_index: usize,
        terminator_mask: u32,
    ) {
        if member_seqs.len() < 2 {
            return;
        }
        // Merge into an existing block when the same member set already has a
        // parity (the two parity frames of one block arrive separately).
        if let Some(block) = self
            .blocks
            .iter_mut()
            .find(|block| block.member_seqs == member_seqs)
        {
            while block.parities.len() <= parity_index {
                block.parities.push(None);
            }
            block.parities[parity_index] = Some(parity);
        } else {
            let mut parities = vec![None; parity_index + 1];
            parities[parity_index] = Some(parity);
            self.blocks.push(FecBlock {
                member_seqs,
                parities,
                terminator_mask,
            });
        }
        while self.blocks.len() > self.window {
            self.blocks.remove(0);
        }
    }

    /// Recover block members absent from the mirror. A block is usable when
    /// the number of absent members is at most the number of parity indices it
    /// holds (one missing → need the XOR parity; two missing → need both the
    /// XOR and the GF-weighted parity). When `gap` is `Some`, only recover
    /// targets inside that live missing range; `None` recovers anything
    /// recoverable. Returns recovered frames in seq order, deduplicated by seq.
    fn try_reconstruct(&mut self, gap: Option<(u64, u64)>) -> Vec<VoiceFrame> {
        let mut recovered: Vec<VoiceFrame> = Vec::new();
        for block in &self.blocks {
            let present: Vec<&ReceivedMember> = self
                .received
                .iter()
                .filter(|member| block.member_seqs.contains(&member.seq))
                .collect();
            let missing: Vec<u64> = block
                .member_seqs
                .iter()
                .copied()
                .filter(|seq| !present.iter().any(|member| member.seq == *seq))
                .collect();
            if missing.is_empty() || missing.len() > block.parities.len() {
                continue;
            }
            if let Some((first, last)) = gap {
                if missing.iter().any(|seq| *seq < first || *seq > last) {
                    continue;
                }
            }
            // S0 = XOR of the present members; S1 = GF(2^8)-weighted XOR of
            // the present members with weight 2^member_index. Both share the
            // present members' common payload length.
            let Some(first_present) = present.first() else {
                continue;
            };
            let member_len = first_present.frame.payload.len();
            let mut s0 = vec![0u8; member_len];
            let mut s1 = vec![0u8; member_len];
            for member in &present {
                let member_index = block
                    .member_seqs
                    .iter()
                    .position(|seq| *seq == member.seq)
                    .unwrap_or(0);
                let coefficient = gf_pow2(member_index as u8);
                for (byte, &value) in member.frame.payload.iter().enumerate() {
                    s0[byte] ^= value;
                    s1[byte] ^= gf_mul(coefficient, value);
                }
            }
            match missing.as_slice() {
                [target] => {
                    // Single recovery: missing = XOR parity ^ all present.
                    let Some(parity0) = block.parity(0) else {
                        continue;
                    };
                    let mut acc = xor_into(parity0, &[]);
                    for member in &present {
                        acc = xor_into(&acc, &member.frame.payload);
                    }
                    if let Some(frame) = recovered_frame(block, &present, *target, Bytes::from(acc))
                    {
                        recovered.push(frame);
                    }
                }
                [a, b] => {
                    // Double recovery: solve the 2x2 system
                    //   t0 = m_a + m_b                (t0 = S0 ^ p0)
                    //   t1 = c_a·m_a + c_b·m_b       (t1 = S1 ^ p1)
                    // as m_a = (t1 + c_b·t0) / (c_a + c_b), m_b = t0 + m_a.
                    let (Some(parity0), Some(parity1)) = (block.parity(0), block.parity(1)) else {
                        continue;
                    };
                    let a_index = block
                        .member_seqs
                        .iter()
                        .position(|seq| *seq == *a)
                        .unwrap_or(0);
                    let b_index = block
                        .member_seqs
                        .iter()
                        .position(|seq| *seq == *b)
                        .unwrap_or(0);
                    let coef_a = gf_pow2(a_index as u8);
                    let coef_b = gf_pow2(b_index as u8);
                    let determinant = coef_a ^ coef_b;
                    let mut m_a = vec![0u8; member_len];
                    let mut m_b = vec![0u8; member_len];
                    for byte in 0..member_len {
                        let t0 = s0[byte] ^ parity0[byte];
                        let t1 = s1[byte] ^ parity1[byte];
                        m_a[byte] = gf_mul(t1 ^ gf_mul(coef_b, t0), gf_inv(determinant));
                        m_b[byte] = t0 ^ m_a[byte];
                    }
                    if let Some(frame) = recovered_frame(block, &present, *a, Bytes::from(m_a)) {
                        recovered.push(frame);
                    }
                    if let Some(frame) = recovered_frame(block, &present, *b, Bytes::from(m_b)) {
                        recovered.push(frame);
                    }
                }
                _ => continue,
            }
        }
        recovered.sort_by_key(|frame| frame.s2s_seq);
        let mut seen = HashSet::new();
        recovered.retain(|frame| seen.insert(frame.s2s_seq));
        recovered
    }
}

/// Build a reconstructed data frame for `target`. Routing metadata (intent,
/// target kind, server id, session, epoch) is copied from the sibling closest
/// in seq — frames of one utterance share it, and the closest sibling is most
/// likely to be in the same utterance. The terminator flag comes from the
/// block's mask. `None` when no present sibling exists to copy metadata from
/// (cannot be routed).
fn recovered_frame(
    block: &FecBlock,
    present: &[&ReceivedMember],
    target: u64,
    payload: Bytes,
) -> Option<VoiceFrame> {
    let template = present
        .iter()
        .min_by_key(|member| member.seq.abs_diff(target))?;
    let member_index = block
        .member_seqs
        .iter()
        .position(|seq| *seq == target)
        .unwrap_or(0);
    let is_terminator = (block.terminator_mask >> member_index) & 1 == 1;
    Some(VoiceFrame {
        sender_session: template.frame.sender_session,
        server_id: template.frame.server_id.clone(),
        sender_epoch: template.frame.sender_epoch,
        s2s_seq: target,
        target_kind: template.frame.target_kind,
        is_terminator,
        payload,
        intent: template.frame.intent.clone(),
        proactive_copy: false,
        fec_parity: false,
        fec_member_seqs: Vec::new(),
        fec_terminator_mask: 0,
        fec_parity_index: 0,
    })
}

/// Sender-side FEC state shared by the voice service's send paths. Each
/// `(sender_session, sender_epoch)` gets its own block window, matching the
/// per-session `s2s_seq` space.
#[derive(Debug)]
pub(crate) struct FecSenderState {
    enabled: bool,
    block_size: usize,
    parity_blocks: usize,
    inner: std::sync::Mutex<HashMap<(u32, u64), SenderFecWindow>>,
}

impl FecSenderState {
    pub(crate) fn new(enabled: bool, block_size: usize, parity_blocks: usize) -> Self {
        // Never more parity than data: the receiver can only recover as many
        // missing members as parity frames it holds, and a block needs at
        // least one surviving data member to copy routing metadata from. Two
        // is the hard ceiling this implementation supports.
        let parity_blocks = parity_blocks.min(block_size.saturating_sub(1)).min(2);
        Self {
            enabled,
            block_size,
            parity_blocks,
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
            .or_insert_with(|| SenderFecWindow::new(self.block_size, self.parity_blocks))
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
        parity_index: usize,
        terminator_mask: u32,
    ) {
        let key = MirrorKey {
            sender_session,
            sender_epoch,
            from,
        };
        let mut inner = self.inner.lock().unwrap();
        let mirror = Self::mirror_mut(&mut inner, key);
        mirror.record_parity(member_seqs, parity, parity_index, terminator_mask);
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
        let key = MirrorKey {
            sender_session,
            sender_epoch,
            from,
        };
        let mut inner = self.inner.lock().unwrap();
        let mirror = Self::mirror_mut(&mut inner, key);
        let recovered = mirror.try_reconstruct(gap);
        for frame in &recovered {
            mirror.record_frame(frame.clone());
        }
        recovered
    }

    fn mirror_mut(inner: &mut ReceiverFecStateInner, key: MirrorKey) -> &mut ReceiverFecWindow {
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
        let tracked = InstantTrackedKey {
            key,
            last_seen: std::time::Instant::now(),
        };
        inner
            .mirrors
            .push((tracked, ReceiverFecWindow::new(inner.window)));
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
            fec_parity_index: 0,
        }
    }

    #[test]
    fn sender_emits_parity_only_on_equal_length_blocks() {
        let mut window = SenderFecWindow::new(4, 1);
        // Frames 1-3 buffered, no parity yet.
        for seq in 1..=3 {
            assert!(
                window
                    .push(seq, Bytes::from_static(b"abcd"), false)
                    .is_none()
            );
        }
        // Frame 4 completes the block.
        let block = window.push(4, Bytes::from_static(b"abcd"), false).unwrap();
        assert_eq!(block.member_seqs, vec![1, 2, 3, 4]);
        assert_eq!(block.parity.len(), 4);
        assert_eq!(block.terminator_mask, 0);
    }

    #[test]
    fn sender_discards_block_on_length_change() {
        let mut window = SenderFecWindow::new(4, 1);
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
        mirror.record_parity(vec![1, 2, 3, 4], Bytes::from_static(b"QWX\x00"), 0, 0);
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
        mirror.record_parity(vec![1, 2, 3, 4], Bytes::from_static(b"zzzz"), 0, 0);
        assert!(mirror.try_reconstruct(None).is_empty());
    }

    #[test]
    fn receiver_restores_terminator_flag() {
        let mut mirror = ReceiverFecWindow::new(8);
        mirror.record_frame(frame(1, b"abcd", false));
        mirror.record_frame(frame(2, b"efgh", false));
        mirror.record_frame(frame(3, b"ijkl", false));
        // Member 4 (index 3) was a terminator.
        mirror.record_parity(vec![1, 2, 3, 4], Bytes::from_static(b"QWX\x00"), 0, 1 << 3);
        let recovered = mirror.try_reconstruct(None);
        assert_eq!(recovered.len(), 1);
        assert!(recovered[0].is_terminator);
    }

    #[test]
    fn sender_emits_two_parities_when_configured() {
        let mut window = SenderFecWindow::new(4, 2);
        for seq in 1..=3 {
            assert!(
                window
                    .push(seq, Bytes::from(vec![seq as u8; 3]), false)
                    .is_none()
            );
        }
        let block = window
            .push(4, Bytes::from(vec![4u8; 3]), false)
            .expect("fourth frame completes the block");
        assert_eq!(block.member_seqs, vec![1, 2, 3, 4]);
        // parity2 = 2^0·m1 ^ 2^1·m2 ^ 2^2·m3 ^ 2^3·m4, all bytes equal here.
        let expected = 1 ^ gf_mul(2, 2) ^ gf_mul(4, 3) ^ gf_mul(8, 4);
        let parity2 = block.parity2.expect("second parity emitted");
        assert_eq!(parity2.as_ref(), [expected, expected, expected].as_slice());
        // Single-parity configuration carries no second parity.
        let mut single = SenderFecWindow::new(4, 1);
        let block = (1..=4)
            .filter_map(|seq| single.push(seq, Bytes::from_static(b"abcd"), false))
            .next()
            .expect("fourth frame completes the block");
        assert!(block.parity2.is_none());
    }

    #[test]
    fn receiver_recovers_two_missing_members_with_two_parities() {
        let mut mirror = ReceiverFecWindow::new(8);
        mirror.record_frame(frame(1, b"abcd", false));
        mirror.record_frame(frame(2, b"efgh", false));
        // Block [1,2,3,4]: both parity frames arrive; members 3 and 4 are
        // missing on the wire.
        let members: [&[u8]; 4] = [b"abcd", b"efgh", b"ijkl", b"mnop"];
        let parity0 = xor_payloads(&members);
        let mut parity1 = vec![0u8; 4];
        for (index, member) in members.iter().enumerate() {
            let coefficient = gf_pow2(index as u8);
            for (byte, &value) in member.iter().enumerate() {
                parity1[byte] ^= gf_mul(coefficient, value);
            }
        }
        // Sanity anchor on the GF arithmetic: byte 0 of parity1, hand-computed.
        assert_eq!(parity1[0], 0x51);
        mirror.record_parity(vec![1, 2, 3, 4], Bytes::from(parity0), 0, 0);
        mirror.record_parity(vec![1, 2, 3, 4], Bytes::from(parity1), 1, 0);
        let recovered = mirror.try_reconstruct(None);
        assert_eq!(recovered.len(), 2);
        let by_seq: HashMap<u64, Vec<u8>> = recovered
            .iter()
            .map(|f| (f.s2s_seq, f.payload.to_vec()))
            .collect();
        assert_eq!(by_seq.get(&3).map(Vec::as_slice), Some(b"ijkl".as_slice()));
        assert_eq!(by_seq.get(&4).map(Vec::as_slice), Some(b"mnop".as_slice()));
    }

    #[test]
    fn receiver_needs_both_parities_for_two_missing_members() {
        let mut mirror = ReceiverFecWindow::new(8);
        mirror.record_frame(frame(1, b"abcd", false));
        mirror.record_frame(frame(2, b"efgh", false));
        // Only the weighted parity arrived: the 2x2 system cannot be solved.
        mirror.record_parity(vec![1, 2, 3, 4], Bytes::from_static(b"Q\x00\x00\x00"), 1, 0);
        assert!(mirror.try_reconstruct(None).is_empty());
    }

    #[test]
    fn receiver_merges_two_parity_frames_into_one_block() {
        let mut mirror = ReceiverFecWindow::new(8);
        mirror.record_frame(frame(1, b"abcd", false));
        mirror.record_frame(frame(2, b"efgh", false));
        // Weighted parity arrives first, then the XOR sum for the same block.
        mirror.record_parity(vec![1, 2, 3, 4], Bytes::from_static(b"Q\x00\x00\x00"), 1, 0);
        mirror.record_parity(
            vec![1, 2, 3, 4],
            Bytes::from_static(b"\x00\x00\x00\x00"),
            0,
            0,
        );
        let recovered = mirror.try_reconstruct(None);
        assert_eq!(recovered.len(), 2);
    }
}
