//! Change-set C3: interleaved Reed-Solomon FEC over the datagram voice lane.
//!
//! The sender deals consecutive frames of one speaker stream round-robin into
//! `voice_fec_interleave_depth` open blocks. When a block holds
//! `voice_fec_block_size` members it owes `voice_fec_parity_blocks` parity
//! frames: a systematic Cauchy Reed-Solomon code over GF(2^8), so any
//! `block_size` of the block's `block_size + parity` frames recover every
//! member. Interleaving spreads a burst of consecutive losses across blocks
//! (a burst of up to `parity × depth` frames costs each block at most
//! `parity` members). An utterance terminator flushes every partial block so
//! the tail of an utterance is protected too.
//!
//! Burst resistance comes from two further kinds of diversity:
//!
//! - Time: a block's parity rows are paced one per subsequent data frame
//!   (row 0 with the frame that completed the block, row 1 with the next,
//!   ...) instead of leaving back-to-back. Packets sent in the same instant
//!   share a congestion drop; spread rows survive the burst that took the
//!   data. After a terminator the remaining rows follow at
//!   [`TAIL_PARITY_SPACING`] intervals.
//! - Path: the caller sends parity over the route's loop-free alternate first
//!   hop when [`parity_alternate_usable`] says its measured metrics can carry
//!   it, so a burst on the data path cannot also take the parity.
//!
//! Each member is coded as a symbol `[len_hi, len_lo, payload.., 0-padding]`
//! padded to the longest member, so members need not share a length and a
//! recovered symbol carries its own payload length.
//!
//! Parity frames are not charged to any byte budget: the sender only skips
//! them while the chosen first hop's datagram lane is shedding at the send
//! path, where they would be discarded before the wire anyway.
//!
//! Wire compatibility: parity indices 0 and 1 belonged to the retired XOR /
//! 2^i scheme. Reed-Solomon parity `j` travels as wire index
//! [`RS_PARITY_INDEX_BASE`] `+ j`. Receivers predating this scheme only solve
//! with indices 0 and 1 and so ignore it, and this receiver ignores indices
//! below the base, so mixed versions never decode each other's parity.
//!
//! The receiver mirrors recent data frames per `(sender_session,
//! sender_epoch)` — not per delivering peer, since parity and data may arrive
//! over different paths — and retains received parity blocks. Reconstruction
//! runs whenever a parity or data frame arrives and recovers the members the
//! reorder still wants. Recovered frames enter the reorder as
//! [`crate::application::voice::reorder::VoiceCopyKind::Fec`].
//!
//! Sliding-window parity is the low-latency alternative, used toward
//! receivers that advertise it (see `voice::capability`). Every protectable
//! data frame is followed at once by one parity equation over the last
//! `voice_fec_sliding_window` members, so a single loss is solvable the moment
//! the parity sent with the lost frame arrives — a block code has to wait for
//! its block to complete first, which can be several frames after the
//! receiver's reorder released past the hole. Consecutive equations overlap,
//! so a burst up to the window is solvable jointly from the equations that
//! cover it. The overhead is one parity frame per data frame, like the
//! default block shape. Sliding parity travels on wire indices
//! [`SLIDING_PARITY_INDEX_BASE`] `+ tail_step`, which block-only receivers
//! already ignore.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use shitspeak_core::NodeIdentifier;

use crate::application::proto::{self, VoiceFrame};
use crate::overlay::VoiceRouteQuality;

/// Upper bound on data members per block (the terminator mask is 32 bits).
pub(crate) const MAX_BLOCK_MEMBERS: usize = 32;
/// Upper bound on parity frames per block.
pub(crate) const MAX_PARITY_FRAMES: usize = 16;
/// Upper bound on interleaved blocks per stream.
pub(crate) const MAX_INTERLEAVE_DEPTH: usize = 8;
/// Wire `fec_parity_index` of Reed-Solomon parity row 0.
pub(crate) const RS_PARITY_INDEX_BASE: u32 = 2;
/// Wire `fec_parity_index` of sliding-window parity sent with its newest
/// member; the paced tail after a terminator adds its step.
pub(crate) const SLIDING_PARITY_INDEX_BASE: u32 = 64;
/// Upper bound on members one sliding-window parity covers.
pub(crate) const MAX_SLIDING_WINDOW: usize = 16;
/// Spacing of parity rows still owed when an utterance ends, standing in for
/// the data frames that would otherwise have paced them.
pub(crate) const TAIL_PARITY_SPACING: Duration = Duration::from_millis(20);
/// Extra one-way latency the alternate path may add over the primary and
/// still deliver parity inside the receiver's late-fill window.
const ALTERNATE_MAX_EXTRA_LATENCY_US: u64 = 100_000;
/// Loss the alternate path may carry beyond 1.5× the primary's and still be
/// preferred for parity: an independent path with comparable loss still
/// decorrelates bursts.
const ALTERNATE_LOSS_ALLOWANCE_PPM: u32 = 20_000;

const LENGTH_PREFIX: usize = 2;
/// A sender stream or receiver mirror unused this long is dropped: the next
/// frame of a resumed speaker starts fresh blocks.
const STREAM_IDLE: Duration = Duration::from_secs(5);
const PRUNE_INTERVAL: Duration = Duration::from_secs(1);

/// Whether a FEC parity frame left toward the lane or failed before it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FecSendOutcome {
    Sent,
    Shed,
}

/// Which first hop carried a parity frame relative to its block's data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FecParityPath {
    /// The data frames' own first hop.
    Primary,
    /// The route's loop-free alternate first hop.
    Alternate,
    /// The data's distribution tree, edge by edge along each binding.
    Tree,
}

impl FecParityPath {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Alternate => "alternate",
            Self::Tree => "tree",
        }
    }
}

/// Whether parity for a destination should ride the route's alternate first
/// hop, from the route's measured metrics: an alternate exists with live
/// transport metrics, its datagram lane is not shedding, its loss is
/// comparable to the primary's, and its extra latency still lands parity
/// inside the receiver's late-fill window. The primary loss is the worse of
/// the selected transport and its datagram lane.
pub(crate) fn parity_alternate_usable(
    quality: VoiceRouteQuality,
    alternate_lane_shedding: bool,
) -> bool {
    let (Some(_), Some(alternate_loss), Some(alternate_latency)) = (
        quality.alternate_next_hop(),
        quality.alternate_loss_ppm(),
        quality.alternate_path_latency_us(),
    ) else {
        return false;
    };
    if alternate_lane_shedding {
        return false;
    }
    let primary_loss = quality
        .loss_ppm()
        .max(quality.datagram_loss_ppm().unwrap_or(0));
    let loss_ceiling = primary_loss
        .saturating_mul(3)
        .saturating_div(2)
        .saturating_add(ALTERNATE_LOSS_ALLOWANCE_PPM);
    alternate_loss <= loss_ceiling
        && alternate_latency
            <= quality
                .path_latency_us()
                .saturating_add(ALTERNATE_MAX_EXTRA_LATENCY_US)
}

/// Minimum receiver mirror length for a sender coding `block_size` members at
/// `depth` interleaving, or sliding parity over `sliding_window` members: two
/// full spans, so every member is still mirrored when its last parity arrives.
pub(crate) fn receiver_window_for(
    configured: usize,
    block_size: usize,
    depth: usize,
    sliding_window: usize,
) -> usize {
    configured
        .max(2 * block_size.max(1) * depth.max(1))
        .max(2 * sliding_window.min(MAX_SLIDING_WINDOW))
}

/// Map a wire parity index to its Reed-Solomon row, or `None` for the retired
/// XOR / 2^i indices.
pub(crate) fn rs_parity_row(wire_index: u32) -> Option<usize> {
    let row = wire_index.checked_sub(RS_PARITY_INDEX_BASE)? as usize;
    (row < MAX_PARITY_FRAMES).then_some(row)
}

/// Map a wire parity index to a sliding-window tail step, or `None` outside
/// the sliding range.
pub(crate) fn sliding_parity_step(wire_index: u32) -> Option<u32> {
    let step = wire_index.checked_sub(SLIDING_PARITY_INDEX_BASE)?;
    (step < MAX_SLIDING_WINDOW as u32).then_some(step)
}

// ---------------------------------------------------------------------------
// GF(2^8) over x^8 + x^4 + x^3 + x^2 + 1 (0x11d), in which 2 is primitive.

struct GfTables {
    exp: [u8; 512],
    log: [u8; 256],
}

static GF: LazyLock<GfTables> = LazyLock::new(|| {
    let mut exp = [0u8; 512];
    let mut log = [0u8; 256];
    let mut x: u16 = 1;
    // `exp` repeats with period 255 so `exp[log a + log b]` needs no modulo.
    for (power, slot) in exp.iter_mut().enumerate() {
        *slot = x as u8;
        if power < 255 {
            log[x as usize] = power as u8;
        }
        x <<= 1;
        if x & 0x100 != 0 {
            x ^= 0x11d;
        }
    }
    GfTables { exp, log }
});

fn gf_mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let gf = &*GF;
    gf.exp[gf.log[a as usize] as usize + gf.log[b as usize] as usize]
}

fn gf_inv(a: u8) -> u8 {
    debug_assert!(a != 0);
    let gf = &*GF;
    gf.exp[255 - gf.log[a as usize] as usize]
}

/// `dst ^= coefficient · src`, over the shorter of the two.
fn mul_acc(dst: &mut [u8], src: &[u8], coefficient: u8) {
    match coefficient {
        0 => {}
        1 => {
            for (d, s) in dst.iter_mut().zip(src) {
                *d ^= *s;
            }
        }
        _ => {
            let gf = &*GF;
            let log_c = gf.log[coefficient as usize] as usize;
            for (d, &s) in dst.iter_mut().zip(src) {
                if s != 0 {
                    *d ^= gf.exp[log_c + gf.log[s as usize] as usize];
                }
            }
        }
    }
}

/// Cauchy generator coefficient `1 / (x_row + y_member)` with
/// `x_row = MAX_BLOCK_MEMBERS + row` and `y_member = member`. The x and y sets
/// are disjoint, so every square submatrix is invertible: any `k` surviving
/// frames of a block determine all `k` members.
fn coefficient(row: usize, member: usize) -> u8 {
    debug_assert!(row < MAX_PARITY_FRAMES && member < MAX_BLOCK_MEMBERS);
    gf_inv(((MAX_BLOCK_MEMBERS + row) as u8) ^ (member as u8))
}

/// Identity of one sliding-window parity equation: its newest member and
/// tail step. Distinct equations near each other get distinct identities.
fn sliding_parity_id(newest_member: u64, step: u32) -> u64 {
    newest_member
        .wrapping_mul(MAX_SLIDING_WINDOW as u64)
        .wrapping_add(u64::from(step))
}

/// Cauchy coefficient of member `member_seq` in sliding equation `parity_id`:
/// `1 / (x + y)` with `x = 128 + parity_id mod 127` and `y = member_seq mod
/// 128`. The x and y ranges are disjoint, so with distinct x and y every
/// square submatrix is invertible. A rare collision between equations or
/// members far apart only costs recovery power: the solver never pins an
/// unknown the equations do not determine.
fn sliding_coefficient(parity_id: u64, member_seq: u64) -> u8 {
    let x = 128 + (parity_id % 127) as u8;
    let y = (member_seq % 128) as u8;
    gf_inv(x ^ y)
}

/// Accumulate `coefficient · symbol(payload)` into `acc`, where the symbol is
/// the payload behind its big-endian length prefix, zero-padded.
fn mul_acc_symbol(acc: &mut [u8], payload: &[u8], coefficient: u8) {
    let len = (payload.len() as u16).to_be_bytes();
    mul_acc(&mut acc[..LENGTH_PREFIX], &len, coefficient);
    mul_acc(&mut acc[LENGTH_PREFIX..], payload, coefficient);
}

/// Invert a square matrix over GF(2^8) by Gauss-Jordan elimination.
fn invert(mut matrix: Vec<Vec<u8>>) -> Option<Vec<Vec<u8>>> {
    let n = matrix.len();
    let mut inverse: Vec<Vec<u8>> = (0..n)
        .map(|row| (0..n).map(|col| u8::from(row == col)).collect())
        .collect();
    for col in 0..n {
        let pivot = (col..n).find(|&row| matrix[row][col] != 0)?;
        matrix.swap(col, pivot);
        inverse.swap(col, pivot);
        let scale = gf_inv(matrix[col][col]);
        for value in matrix[col].iter_mut() {
            *value = gf_mul(*value, scale);
        }
        for value in inverse[col].iter_mut() {
            *value = gf_mul(*value, scale);
        }
        for row in 0..n {
            let factor = matrix[row][col];
            if row == col || factor == 0 {
                continue;
            }
            for k in 0..n {
                let m = gf_mul(factor, matrix[col][k]);
                matrix[row][k] ^= m;
                let i = gf_mul(factor, inverse[col][k]);
                inverse[row][k] ^= i;
            }
        }
    }
    Some(inverse)
}

// ---------------------------------------------------------------------------
// Sender.

/// A completed block ready to be encoded onto the wire.
#[derive(Debug, Clone)]
pub(crate) struct FecBlockToSend {
    pub(crate) member_seqs: Vec<u64>,
    /// Reed-Solomon parity rows `0..parities.len()`.
    pub(crate) parities: Vec<Bytes>,
    /// Bit `i` set when block member `i` was an utterance terminator.
    pub(crate) terminator_mask: u32,
}

impl FecBlockToSend {
    pub(crate) fn encode(
        &self,
        sender_session: u32,
        sender_epoch: u64,
        row: usize,
    ) -> Option<Bytes> {
        let payload = self.parities.get(row)?.clone();
        let frame = VoiceFrame {
            sender_session,
            server_id: String::new(),
            sender_epoch,
            s2s_seq: self.member_seqs.last().copied().unwrap_or(0),
            target_kind: 0,
            is_terminator: false,
            payload,
            intent: None,
            proactive_copy: false,
            fec_parity: true,
            fec_member_seqs: self.member_seqs.clone(),
            fec_terminator_mask: self.terminator_mask,
            fec_parity_index: RS_PARITY_INDEX_BASE + row as u32,
        };
        proto::encode_voice(&frame).ok()
    }
}

#[derive(Debug)]
struct PendingMember {
    seq: u64,
    payload: Bytes,
    terminator: bool,
}

fn encode_block(members: Vec<PendingMember>, parity_frames: usize) -> FecBlockToSend {
    let symbol_len = LENGTH_PREFIX
        + members
            .iter()
            .map(|member| member.payload.len())
            .max()
            .unwrap_or(0);
    let parities = (0..parity_frames)
        .map(|row| {
            let mut acc = vec![0u8; symbol_len];
            for (index, member) in members.iter().enumerate() {
                mul_acc_symbol(&mut acc, &member.payload, coefficient(row, index));
            }
            Bytes::from(acc)
        })
        .collect();
    let mut terminator_mask = 0u32;
    for (index, member) in members.iter().enumerate() {
        if member.terminator {
            terminator_mask |= 1 << index;
        }
    }
    FecBlockToSend {
        member_seqs: members.iter().map(|member| member.seq).collect(),
        parities,
        terminator_mask,
    }
}

/// One sliding-window parity equation ready to be encoded onto the wire.
#[derive(Debug)]
pub(crate) struct SlidingParityToSend {
    member_seqs: Vec<u64>,
    parity: Bytes,
    terminator_mask: u32,
    step: u32,
}

impl SlidingParityToSend {
    fn encode(&self, sender_session: u32, sender_epoch: u64) -> Option<Bytes> {
        let frame = VoiceFrame {
            sender_session,
            server_id: String::new(),
            sender_epoch,
            s2s_seq: self.member_seqs.last().copied().unwrap_or(0),
            target_kind: 0,
            is_terminator: false,
            payload: self.parity.clone(),
            intent: None,
            proactive_copy: false,
            fec_parity: true,
            fec_member_seqs: self.member_seqs.clone(),
            fec_terminator_mask: self.terminator_mask,
            fec_parity_index: SLIDING_PARITY_INDEX_BASE + self.step,
        };
        proto::encode_voice(&frame).ok()
    }
}

fn encode_sliding(window: &VecDeque<PendingMember>, step: u32) -> SlidingParityToSend {
    // Members are coded in seq order, whatever order they were pushed in
    // (proactive copies leave a queue out of order): the equation's identity
    // is its newest seq, which is all the receiver can derive from the wire.
    let mut window: Vec<&PendingMember> = window.iter().collect();
    window.sort_unstable_by_key(|member| member.seq);
    let member_seqs: Vec<u64> = window.iter().map(|member| member.seq).collect();
    let parity_id = sliding_parity_id(member_seqs.last().copied().unwrap_or(0), step);
    let symbol_len = LENGTH_PREFIX
        + window
            .iter()
            .map(|member| member.payload.len())
            .max()
            .unwrap_or(0);
    let mut acc = vec![0u8; symbol_len];
    let mut terminator_mask = 0u32;
    for (index, member) in window.iter().enumerate() {
        mul_acc_symbol(
            &mut acc,
            &member.payload,
            sliding_coefficient(parity_id, member.seq),
        );
        if member.terminator {
            terminator_mask |= 1 << index;
        }
    }
    SlidingParityToSend {
        member_seqs,
        parity: Bytes::from(acc),
        terminator_mask,
        step,
    }
}

#[derive(Debug, Clone)]
enum ParitySource {
    /// Row `row` of a Reed-Solomon block.
    Block {
        block: Arc<FecBlockToSend>,
        row: usize,
    },
    Sliding(Arc<SlidingParityToSend>),
}

/// One parity frame the sender owes now, to be sent after
/// `tail_step × TAIL_PARITY_SPACING` (step 0 is immediate).
#[derive(Debug, Clone)]
pub(crate) struct ParityEmission {
    source: ParitySource,
    pub(crate) tail_step: u32,
}

impl ParityEmission {
    pub(crate) fn encode(&self, sender_session: u32, sender_epoch: u64) -> Option<Bytes> {
        match &self.source {
            ParitySource::Block { block, row } => block.encode(sender_session, sender_epoch, *row),
            ParitySource::Sliding(parity) => parity.encode(sender_session, sender_epoch),
        }
    }

    pub(crate) fn delay(&self) -> Duration {
        TAIL_PARITY_SPACING * self.tail_step
    }

    #[cfg(test)]
    pub(crate) fn member_seqs(&self) -> &[u64] {
        match &self.source {
            ParitySource::Block { block, .. } => &block.member_seqs,
            ParitySource::Sliding(parity) => &parity.member_seqs,
        }
    }

    #[cfg(test)]
    pub(crate) fn terminator_mask(&self) -> u32 {
        match &self.source {
            ParitySource::Block { block, .. } => block.terminator_mask,
            ParitySource::Sliding(parity) => parity.terminator_mask,
        }
    }

    /// The `fec_parity_index` this emission travels with.
    #[cfg(test)]
    pub(crate) fn wire_index(&self) -> u32 {
        match &self.source {
            ParitySource::Block { row, .. } => RS_PARITY_INDEX_BASE + *row as u32,
            ParitySource::Sliding(parity) => SLIDING_PARITY_INDEX_BASE + parity.step,
        }
    }
}

/// A completed block whose parity rows are still being paced out.
#[derive(Debug)]
struct EmittingBlock {
    block: Arc<FecBlockToSend>,
    next_row: usize,
}

/// One speaker stream's interleaved open blocks and paced parity.
#[derive(Debug)]
struct SenderFecStream {
    lanes: Vec<Vec<PendingMember>>,
    next_lane: usize,
    emitting: Vec<EmittingBlock>,
}

impl SenderFecStream {
    fn new(depth: usize) -> Self {
        Self {
            lanes: (0..depth).map(|_| Vec::new()).collect(),
            next_lane: 0,
            emitting: Vec::new(),
        }
    }

    /// Add the next sent frame to the next interleaved block and return the
    /// parity now due: the next row of every block still owing parity (the
    /// block this frame completed included). A terminator also completes every
    /// partial block and schedules all remaining rows as a paced tail.
    fn push(
        &mut self,
        block_size: usize,
        parity_frames: usize,
        member: PendingMember,
    ) -> Vec<ParityEmission> {
        let terminator = member.terminator;
        let protectable =
            !member.payload.is_empty() && member.payload.len() <= usize::from(u16::MAX);
        let duplicate = self
            .lanes
            .iter()
            .flatten()
            .any(|pending| pending.seq == member.seq);
        if duplicate {
            return Vec::new();
        }
        if protectable {
            let lane = self.next_lane;
            self.next_lane = (lane + 1) % self.lanes.len();
            self.lanes[lane].push(member);
            if self.lanes[lane].len() >= block_size {
                let members = std::mem::take(&mut self.lanes[lane]);
                self.start_emitting(encode_block(members, parity_frames));
            }
        }
        if terminator {
            for lane in 0..self.lanes.len() {
                if !self.lanes[lane].is_empty() {
                    let members = std::mem::take(&mut self.lanes[lane]);
                    self.start_emitting(encode_block(members, parity_frames));
                }
            }
            self.next_lane = 0;
        }
        let mut due = Vec::new();
        for emitting in &mut self.emitting {
            due.push(ParityEmission {
                source: ParitySource::Block {
                    block: emitting.block.clone(),
                    row: emitting.next_row,
                },
                tail_step: 0,
            });
            emitting.next_row += 1;
        }
        if terminator {
            for emitting in self.emitting.drain(..) {
                for (step, row) in (emitting.next_row..emitting.block.parities.len()).enumerate() {
                    due.push(ParityEmission {
                        source: ParitySource::Block {
                            block: emitting.block.clone(),
                            row,
                        },
                        tail_step: step as u32 + 1,
                    });
                }
            }
        } else {
            self.emitting
                .retain(|emitting| emitting.next_row < emitting.block.parities.len());
        }
        due
    }

    fn start_emitting(&mut self, block: FecBlockToSend) {
        self.emitting.push(EmittingBlock {
            block: Arc::new(block),
            next_row: 0,
        });
    }
}

/// One speaker stream's sliding window of the most recent protectable
/// members.
#[derive(Debug)]
struct SenderSlidingStream {
    window: VecDeque<PendingMember>,
}

impl SenderSlidingStream {
    fn new() -> Self {
        Self {
            window: VecDeque::new(),
        }
    }

    /// Add the next sent frame to the window and return the parity now due:
    /// one equation over the window, sent with the frame. A terminator also
    /// schedules `window − 1` further equations over the final window as a
    /// paced tail — together with the one sent with each member they solve a
    /// loss of the whole final window — and starts the next utterance empty.
    fn push(&mut self, window: usize, member: PendingMember) -> Vec<ParityEmission> {
        let terminator = member.terminator;
        let protectable =
            !member.payload.is_empty() && member.payload.len() <= usize::from(u16::MAX);
        if self.window.iter().any(|pending| pending.seq == member.seq) {
            return Vec::new();
        }
        let mut due = Vec::new();
        if protectable {
            self.window.push_back(member);
            while self.window.len() > window {
                self.window.pop_front();
            }
            due.push(ParityEmission {
                source: ParitySource::Sliding(Arc::new(encode_sliding(&self.window, 0))),
                tail_step: 0,
            });
        }
        if terminator {
            for step in 1..self.window.len() as u32 {
                due.push(ParityEmission {
                    source: ParitySource::Sliding(Arc::new(encode_sliding(&self.window, step))),
                    tail_step: step,
                });
            }
            self.window.clear();
        }
        due
    }
}

/// Which code protects one sender stream.
#[derive(Debug)]
enum SenderStream {
    Block(SenderFecStream),
    Sliding(SenderSlidingStream),
}

/// Sender-side FEC state shared by the voice service's send paths. Each
/// speaker, first hop, and recipient set gets its own interleaved blocks, so
/// a block never spans links or mixes frames sent to different recipients.
#[derive(Debug)]
pub(crate) struct FecSenderState {
    block_size: usize,
    parity_frames: usize,
    depth: usize,
    sliding_window: usize,
    inner: std::sync::Mutex<FecSenderInner>,
}

#[derive(Debug)]
struct FecSenderInner {
    streams: HashMap<FecStreamKey, (SenderStream, Instant)>,
    last_prune: Instant,
}

/// The code is part of the key: when a recipient set's capability changes,
/// the new code starts a fresh stream instead of mixing equations.
#[derive(Debug, PartialEq, Eq, Hash)]
struct FecStreamKey {
    sender_session: u32,
    sender_epoch: u64,
    first_hop: NodeIdentifier,
    destinations: Vec<NodeIdentifier>,
    sliding: bool,
}

impl FecSenderState {
    pub(crate) fn new(block_size: usize, parity_frames: usize, depth: usize) -> Self {
        Self {
            block_size: block_size.clamp(1, MAX_BLOCK_MEMBERS),
            parity_frames: parity_frames.clamp(1, MAX_PARITY_FRAMES),
            depth: depth.clamp(1, MAX_INTERLEAVE_DEPTH),
            sliding_window: 0,
            inner: std::sync::Mutex::new(FecSenderInner {
                streams: HashMap::new(),
                last_prune: Instant::now(),
            }),
        }
    }

    /// Enable sliding-window parity over `window` members toward recipients
    /// that advertise it. A window below 2 keeps every stream on the block
    /// code.
    pub(crate) fn with_sliding_window(mut self, window: usize) -> Self {
        self.sliding_window = if window < 2 {
            0
        } else {
            window.min(MAX_SLIDING_WINDOW)
        };
        self
    }

    /// Whether any stream may use sliding-window parity. Callers skip the
    /// recipient capability lookup when it may not.
    pub(crate) fn sliding_enabled(&self) -> bool {
        self.sliding_window >= 2
    }

    /// Push a sent frame into its block-code stream. Returns the parity it
    /// made due.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn push(
        &self,
        first_hop: NodeIdentifier,
        destinations: &[NodeIdentifier],
        sender_session: u32,
        sender_epoch: u64,
        seq: u64,
        payload: Bytes,
        terminator: bool,
    ) -> Vec<ParityEmission> {
        self.push_with_code(
            first_hop,
            destinations,
            sender_session,
            sender_epoch,
            seq,
            payload,
            terminator,
            false,
        )
    }

    /// Push a sent frame into its stream, coded with sliding-window parity
    /// when `sliding` (every recipient advertises it) and sliding parity is
    /// enabled, else the block code. Returns the parity it made due.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn push_with_code(
        &self,
        first_hop: NodeIdentifier,
        destinations: &[NodeIdentifier],
        sender_session: u32,
        sender_epoch: u64,
        seq: u64,
        payload: Bytes,
        terminator: bool,
        sliding: bool,
    ) -> Vec<ParityEmission> {
        let sliding = sliding && self.sliding_enabled();
        let mut destinations = destinations.to_vec();
        destinations.sort_unstable();
        destinations.dedup();
        let now = Instant::now();
        let mut inner = self.inner.lock().unwrap();
        if now.saturating_duration_since(inner.last_prune) >= PRUNE_INTERVAL {
            inner.last_prune = now;
            inner.streams.retain(|_, (_, last_used)| {
                now.saturating_duration_since(*last_used) < STREAM_IDLE
            });
        }
        let (stream, last_used) = inner
            .streams
            .entry(FecStreamKey {
                sender_session,
                sender_epoch,
                first_hop,
                destinations,
                sliding,
            })
            .or_insert_with(|| {
                let stream = if sliding {
                    SenderStream::Sliding(SenderSlidingStream::new())
                } else {
                    SenderStream::Block(SenderFecStream::new(self.depth))
                };
                (stream, now)
            });
        *last_used = now;
        let member = PendingMember {
            seq,
            payload,
            terminator,
        };
        match stream {
            SenderStream::Block(stream) => stream.push(self.block_size, self.parity_frames, member),
            SenderStream::Sliding(stream) => stream.push(self.sliding_window, member),
        }
    }
}

// ---------------------------------------------------------------------------
// Receiver.

/// A received parity block.
#[derive(Debug)]
struct FecBlock {
    member_seqs: Vec<u64>,
    /// Indexed by Reed-Solomon row; `Some` once that parity frame arrived.
    parities: Vec<Option<Bytes>>,
    terminator_mask: u32,
    /// Every member is present or recovered; nothing left to solve.
    resolved: bool,
}

/// A received sliding-window parity equation.
#[derive(Debug)]
struct SlidingEquation {
    member_seqs: Vec<u64>,
    parity: Bytes,
    terminator_mask: u32,
    parity_id: u64,
}

/// Receiver-side mirror of recent data frames and parity blocks for one
/// `(sender_session, sender_epoch)`, whichever peers delivered them.
#[derive(Debug)]
struct ReceiverFecWindow {
    window: usize,
    received: VecDeque<VoiceFrame>,
    blocks: VecDeque<FecBlock>,
    /// Sliding-window equations that still cover an absent member.
    equations: VecDeque<SlidingEquation>,
    /// Reconstructed members the reorder did not want yet — typically frames
    /// whose originals were only in flight. Released once they become a hole
    /// the reorder waits on, dropped when their original arrives.
    stash: VecDeque<VoiceFrame>,
    last_used: Instant,
}

impl ReceiverFecWindow {
    fn new(window: usize, now: Instant) -> Self {
        Self {
            window: window.max(1),
            received: VecDeque::new(),
            blocks: VecDeque::new(),
            equations: VecDeque::new(),
            stash: VecDeque::new(),
            last_used: now,
        }
    }

    /// Record an inbound data frame (any copy kind). Keeps the most recent
    /// copy of each seq so a replayed original cannot double-count a member.
    fn record_frame(&mut self, frame: VoiceFrame) {
        let seq = frame.s2s_seq;
        self.stash.retain(|stashed| stashed.s2s_seq != seq);
        self.mirror_frame(frame);
    }

    fn mirror_frame(&mut self, frame: VoiceFrame) {
        let seq = frame.s2s_seq;
        self.received.retain(|member| member.s2s_seq != seq);
        self.received.push_back(frame);
        while self.received.len() > self.window {
            self.received.pop_front();
        }
    }

    fn record_parity(
        &mut self,
        member_seqs: Vec<u64>,
        parity: Bytes,
        row: usize,
        terminator_mask: u32,
    ) {
        if member_seqs.is_empty()
            || member_seqs.len() > MAX_BLOCK_MEMBERS
            || row >= MAX_PARITY_FRAMES
            || parity.len() < LENGTH_PREFIX
        {
            return;
        }
        if let Some(block) = self
            .blocks
            .iter_mut()
            .find(|block| block.member_seqs == member_seqs)
        {
            // Parity frames of one block share the symbol length; a mismatch
            // is not the same block.
            let consistent = block
                .parities
                .iter()
                .flatten()
                .all(|existing| existing.len() == parity.len());
            if !consistent {
                return;
            }
            if block.parities.len() <= row {
                block.parities.resize(row + 1, None);
            }
            block.parities[row] = Some(parity);
            return;
        }
        let mut parities = vec![None; row + 1];
        parities[row] = Some(parity);
        self.blocks.push_back(FecBlock {
            member_seqs,
            parities,
            terminator_mask,
            resolved: false,
        });
        while self.blocks.len() > self.window {
            self.blocks.pop_front();
        }
    }

    fn record_sliding_parity(
        &mut self,
        member_seqs: Vec<u64>,
        parity: Bytes,
        step: u32,
        terminator_mask: u32,
    ) {
        let Some(&newest) = member_seqs.iter().max() else {
            return;
        };
        if member_seqs.len() > MAX_SLIDING_WINDOW || parity.len() < LENGTH_PREFIX {
            return;
        }
        let parity_id = sliding_parity_id(newest, step);
        if self
            .equations
            .iter()
            .any(|equation| equation.parity_id == parity_id && equation.member_seqs == member_seqs)
        {
            return;
        }
        self.equations.push_back(SlidingEquation {
            member_seqs,
            parity,
            terminator_mask,
            parity_id,
        });
        while self.equations.len() > self.window {
            self.equations.pop_front();
        }
    }

    /// Solve every unresolved block that has at least as many parity frames
    /// as absent members, and the sliding-window equations jointly, when the
    /// reorder still wants an absent member. Recovered members are recorded
    /// back into the mirror. Those `wanted` accepts — now or from an earlier
    /// solve — are returned in seq order; the rest wait in the stash.
    fn try_reconstruct(&mut self, wanted: &dyn Fn(u64) -> bool) -> Vec<VoiceFrame> {
        let mut recovered: Vec<VoiceFrame> = Vec::new();
        if self.received.is_empty() {
            // Nothing to copy routing metadata from yet.
            return recovered;
        }
        for block_index in 0..self.blocks.len() {
            let block = &self.blocks[block_index];
            if block.resolved {
                continue;
            }
            let Some(solution) = solve_block(block, &self.received, wanted) else {
                continue;
            };
            self.blocks[block_index].resolved = true;
            let block = &self.blocks[block_index];
            for (member, payload) in solution {
                let seq = block.member_seqs[member];
                let Some(frame) = recovered_frame(block, &self.received, member, seq, payload)
                else {
                    continue;
                };
                recovered.push(frame);
            }
        }
        for frame in &recovered {
            self.mirror_frame(frame.clone());
        }
        // Block recoveries are mirrored first: they are known members of the
        // sliding equations.
        let sliding = self.solve_sliding(wanted);
        for frame in &sliding {
            self.mirror_frame(frame.clone());
        }
        recovered.extend(sliding);
        self.stash.extend(recovered.drain(..));
        self.stash.retain(|frame| {
            if wanted(frame.s2s_seq) {
                recovered.push(frame.clone());
                false
            } else {
                true
            }
        });
        while self.stash.len() > self.window {
            self.stash.pop_front();
        }
        recovered.sort_by_key(|frame| frame.s2s_seq);
        recovered.dedup_by_key(|frame| frame.s2s_seq);
        recovered
    }
}

impl ReceiverFecWindow {
    /// Solve the sliding-window equations jointly for their absent members.
    /// Every equation still covering an absent member contributes one row
    /// over the absent members; the parity minus every mirrored member's
    /// contribution is its right-hand side. Gauss-Jordan elimination pins an
    /// absent member only when its reduced row has no other absent member, so
    /// an under-determined system recovers exactly what it determines and
    /// never guesses. Equations with no absent member left are dropped.
    fn solve_sliding(&mut self, wanted: &dyn Fn(u64) -> bool) -> Vec<VoiceFrame> {
        let received = &self.received;
        let mirrored = |seq: u64| received.iter().find(|frame| frame.s2s_seq == seq);
        self.equations.retain(|equation| {
            equation
                .member_seqs
                .iter()
                .any(|seq| mirrored(*seq).is_none())
        });
        let mut absent: Vec<u64> = self
            .equations
            .iter()
            .flat_map(|equation| equation.member_seqs.iter().copied())
            .filter(|seq| mirrored(*seq).is_none())
            .collect();
        absent.sort_unstable();
        absent.dedup();
        if !absent.iter().any(|seq| wanted(*seq)) {
            return Vec::new();
        }
        let symbol_len = self
            .equations
            .iter()
            .map(|equation| equation.parity.len())
            .max()
            .unwrap_or(0);
        let mut rows: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        for equation in &self.equations {
            // A mirrored frame longer than the equation's symbols is not the
            // member the sender coded; this equation cannot be trusted.
            let consistent = equation.member_seqs.iter().all(|seq| {
                mirrored(*seq).is_none_or(|frame| {
                    frame.payload.len() + LENGTH_PREFIX <= equation.parity.len()
                })
            });
            if !consistent {
                continue;
            }
            let mut coefficients = vec![0u8; absent.len()];
            let mut rhs = vec![0u8; symbol_len];
            rhs[..equation.parity.len()].copy_from_slice(&equation.parity);
            for &seq in &equation.member_seqs {
                let coefficient = sliding_coefficient(equation.parity_id, seq);
                match mirrored(seq) {
                    Some(frame) => mul_acc_symbol(&mut rhs, &frame.payload, coefficient),
                    None => {
                        let column = absent
                            .binary_search(&seq)
                            .expect("every absent member has a column");
                        coefficients[column] = coefficient;
                    }
                }
            }
            rows.push((coefficients, rhs));
        }
        let mut pivots: Vec<(usize, usize)> = Vec::new();
        for column in 0..absent.len() {
            let next = pivots.len();
            let Some(pivot) = (next..rows.len()).find(|&row| rows[row].0[column] != 0) else {
                continue;
            };
            rows.swap(next, pivot);
            let scale = gf_inv(rows[next].0[column]);
            let (coefficients, rhs) = &mut rows[next];
            for value in coefficients.iter_mut().chain(rhs.iter_mut()) {
                *value = gf_mul(*value, scale);
            }
            let (pivot_coefficients, pivot_rhs) = rows[next].clone();
            for (row, (coefficients, rhs)) in rows.iter_mut().enumerate() {
                let factor = coefficients[column];
                if row == next || factor == 0 {
                    continue;
                }
                mul_acc(coefficients, &pivot_coefficients, factor);
                mul_acc(rhs, &pivot_rhs, factor);
            }
            pivots.push((next, column));
        }
        let mut solved = Vec::new();
        for (row, column) in pivots {
            let (coefficients, symbol) = &rows[row];
            if coefficients
                .iter()
                .enumerate()
                .any(|(other, value)| other != column && *value != 0)
            {
                continue;
            }
            let len = usize::from(u16::from_be_bytes([symbol[0], symbol[1]]));
            if len == 0 || LENGTH_PREFIX + len > symbol_len {
                continue;
            }
            let seq = absent[column];
            let is_terminator = self.equations.iter().any(|equation| {
                equation
                    .member_seqs
                    .iter()
                    .position(|member| *member == seq)
                    .is_some_and(|index| (equation.terminator_mask >> index) & 1 == 1)
            });
            let payload = Bytes::copy_from_slice(&symbol[LENGTH_PREFIX..LENGTH_PREFIX + len]);
            if let Some(frame) = frame_from_template(&self.received, seq, payload, is_terminator) {
                solved.push(frame);
            }
        }
        solved
    }
}

/// Recover a block's absent members as `(member_index, payload)`. `None` when
/// nothing is absent (the block is marked resolved by the caller only on
/// `Some`), nothing absent is wanted, or too few parity frames arrived.
fn solve_block(
    block: &FecBlock,
    received: &VecDeque<VoiceFrame>,
    wanted: &dyn Fn(u64) -> bool,
) -> Option<Vec<(usize, Bytes)>> {
    let mut present: Vec<(usize, &VoiceFrame)> = Vec::new();
    let mut missing: Vec<usize> = Vec::new();
    for (index, seq) in block.member_seqs.iter().enumerate() {
        match received.iter().find(|frame| frame.s2s_seq == *seq) {
            Some(frame) => present.push((index, frame)),
            None => missing.push(index),
        }
    }
    if missing.is_empty() {
        return Some(Vec::new());
    }
    if !missing
        .iter()
        .any(|&index| wanted(block.member_seqs[index]))
    {
        return None;
    }
    let rows: Vec<(usize, &Bytes)> = block
        .parities
        .iter()
        .enumerate()
        .filter_map(|(row, parity)| parity.as_ref().map(|parity| (row, parity)))
        .take(missing.len())
        .collect();
    if rows.len() < missing.len() {
        return None;
    }
    let symbol_len = rows[0].1.len();
    if present
        .iter()
        .any(|(_, frame)| frame.payload.len() + LENGTH_PREFIX > symbol_len)
    {
        // A mirrored frame longer than the block's symbols is not the member
        // the sender coded; solving would produce garbage.
        return None;
    }
    // Right-hand side per used parity row: the parity minus the contribution
    // of every present member.
    let rhs: Vec<Vec<u8>> = rows
        .iter()
        .map(|(row, parity)| {
            let mut acc = parity.to_vec();
            for (index, frame) in &present {
                mul_acc_symbol(&mut acc, &frame.payload, coefficient(*row, *index));
            }
            acc
        })
        .collect();
    let system: Vec<Vec<u8>> = rows
        .iter()
        .map(|(row, _)| {
            missing
                .iter()
                .map(|&index| coefficient(*row, index))
                .collect()
        })
        .collect();
    let inverse = invert(system)?;
    let mut solution = Vec::with_capacity(missing.len());
    for (unknown, &member) in missing.iter().enumerate() {
        let mut symbol = vec![0u8; symbol_len];
        for (equation, rhs) in rhs.iter().enumerate() {
            mul_acc(&mut symbol, rhs, inverse[unknown][equation]);
        }
        let len = usize::from(u16::from_be_bytes([symbol[0], symbol[1]]));
        if len == 0 || LENGTH_PREFIX + len > symbol_len {
            return None;
        }
        solution.push((
            member,
            Bytes::copy_from_slice(&symbol[LENGTH_PREFIX..LENGTH_PREFIX + len]),
        ));
    }
    Some(solution)
}

/// Build a reconstructed data frame for block member `member`. Routing
/// metadata (intent, target kind, server id, session, epoch) is copied from
/// the mirrored frame closest in seq — frames of one utterance share it, and
/// with interleaving the nearest frame is often outside the block. The
/// terminator flag comes from the block's mask. `None` when the mirror holds
/// nothing to copy metadata from (the frame could not be routed).
fn recovered_frame(
    block: &FecBlock,
    received: &VecDeque<VoiceFrame>,
    member: usize,
    seq: u64,
    payload: Bytes,
) -> Option<VoiceFrame> {
    let is_terminator = (block.terminator_mask >> member) & 1 == 1;
    frame_from_template(received, seq, payload, is_terminator)
}

/// A reconstructed data frame for `seq`, with routing metadata copied from
/// the mirrored frame closest in seq. `None` when the mirror is empty.
fn frame_from_template(
    received: &VecDeque<VoiceFrame>,
    seq: u64,
    payload: Bytes,
    is_terminator: bool,
) -> Option<VoiceFrame> {
    let template = received
        .iter()
        .min_by_key(|frame| frame.s2s_seq.abs_diff(seq))?;
    Some(VoiceFrame {
        sender_session: template.sender_session,
        server_id: template.server_id.clone(),
        sender_epoch: template.sender_epoch,
        s2s_seq: seq,
        target_kind: template.target_kind,
        is_terminator,
        payload,
        intent: template.intent.clone(),
        proactive_copy: false,
        fec_parity: false,
        fec_member_seqs: Vec::new(),
        fec_terminator_mask: 0,
        fec_parity_index: 0,
    })
}

/// Per-(sender, epoch) receiver FEC state shared with the dispatch task.
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
    mirrors: HashMap<MirrorKey, ReceiverFecWindow>,
    last_prune: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct MirrorKey {
    sender_session: u32,
    sender_epoch: u64,
}

impl ReceiverFecState {
    pub(crate) fn new(window: usize) -> Self {
        Self {
            inner: std::sync::Mutex::new(ReceiverFecStateInner {
                window,
                max_mirrors: 4_096,
                mirrors: HashMap::new(),
                last_prune: Instant::now(),
            }),
        }
    }

    pub(crate) fn record_frame(&self, frame: VoiceFrame) {
        let key = MirrorKey {
            sender_session: frame.sender_session,
            sender_epoch: frame.sender_epoch,
        };
        let mut inner = self.inner.lock().unwrap();
        inner.mirror_mut(key).record_frame(frame);
    }

    /// Record a received parity frame. Returns `false` (and records nothing)
    /// for a wire index outside both the Reed-Solomon and the sliding-window
    /// schemes.
    pub(crate) fn record_parity(
        &self,
        sender_session: u32,
        sender_epoch: u64,
        member_seqs: Vec<u64>,
        parity: Bytes,
        wire_index: u32,
        terminator_mask: u32,
    ) -> bool {
        let key = MirrorKey {
            sender_session,
            sender_epoch,
        };
        if let Some(row) = rs_parity_row(wire_index) {
            let mut inner = self.inner.lock().unwrap();
            inner
                .mirror_mut(key)
                .record_parity(member_seqs, parity, row, terminator_mask);
            return true;
        }
        if let Some(step) = sliding_parity_step(wire_index) {
            let mut inner = self.inner.lock().unwrap();
            inner
                .mirror_mut(key)
                .record_sliding_parity(member_seqs, parity, step, terminator_mask);
            return true;
        }
        false
    }

    /// Reconstruct block members for this sender that `wanted` accepts.
    /// Recovered frames are recorded back into the mirror.
    pub(crate) fn try_reconstruct(
        &self,
        sender_session: u32,
        sender_epoch: u64,
        wanted: &dyn Fn(u64) -> bool,
    ) -> Vec<VoiceFrame> {
        let key = MirrorKey {
            sender_session,
            sender_epoch,
        };
        let mut inner = self.inner.lock().unwrap();
        match inner.mirrors.get_mut(&key) {
            Some(mirror) => mirror.try_reconstruct(wanted),
            None => Vec::new(),
        }
    }
}

impl ReceiverFecStateInner {
    fn mirror_mut(&mut self, key: MirrorKey) -> &mut ReceiverFecWindow {
        let now = Instant::now();
        if now.saturating_duration_since(self.last_prune) >= PRUNE_INTERVAL {
            self.last_prune = now;
            self.mirrors
                .retain(|_, mirror| now.saturating_duration_since(mirror.last_used) < STREAM_IDLE);
        }
        if !self.mirrors.contains_key(&key) && self.mirrors.len() >= self.max_mirrors {
            // Evict the least-recently-used mirror as a memory backstop.
            if let Some(oldest) = self
                .mirrors
                .iter()
                .min_by_key(|(_, mirror)| mirror.last_used)
                .map(|(key, _)| *key)
            {
                self.mirrors.remove(&oldest);
            }
        }
        let window = self.window;
        let mirror = self
            .mirrors
            .entry(key)
            .or_insert_with(|| ReceiverFecWindow::new(window, now));
        mirror.last_used = now;
        mirror
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Encode a Reed-Solomon parity row over `payloads`, as a sender would.
    pub(crate) fn rs_parity(payloads: &[&[u8]], row: usize) -> Vec<u8> {
        let members = payloads
            .iter()
            .enumerate()
            .map(|(index, payload)| PendingMember {
                seq: index as u64,
                payload: Bytes::copy_from_slice(payload),
                terminator: false,
            })
            .collect();
        encode_block(members, row + 1).parities[row].to_vec()
    }

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

    fn payload_for(seq: u64) -> Vec<u8> {
        // Variable-length payloads exercise the length prefix.
        let len = 20 + (seq % 7) as usize;
        (0..len)
            .map(|byte| (seq as u8).wrapping_mul(31).wrapping_add(byte as u8))
            .collect()
    }

    fn any(_: u64) -> bool {
        true
    }

    /// Deterministic xorshift PRNG so the loss simulation is reproducible.
    struct XorShift(u64);

    impl XorShift {
        fn next_unit(&mut self) -> f64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            (self.0 >> 11) as f64 / (1u64 << 53) as f64
        }
    }

    #[test]
    fn gf_tables_are_a_field() {
        for a in 1..=255u8 {
            assert_eq!(gf_mul(a, gf_inv(a)), 1, "inverse of {a}");
        }
        assert_eq!(gf_mul(0x80, 2), 0x1d);
        let gf = &*GF;
        assert!((0..257).all(|power| gf.exp[power] == gf.exp[power + 255]));
    }

    #[test]
    fn every_cauchy_submatrix_of_the_default_code_is_invertible() {
        // Any k surviving frames must determine the block: every square
        // submatrix of rows × members must be invertible.
        let (k, m) = (4usize, 4usize);
        for mask in 1u32..(1 << k) {
            let members: Vec<usize> = (0..k).filter(|i| mask & (1 << i) != 0).collect();
            for row_mask in 1u32..(1 << m) {
                let rows: Vec<usize> = (0..m).filter(|r| row_mask & (1 << r) != 0).collect();
                if rows.len() != members.len() {
                    continue;
                }
                let system = rows
                    .iter()
                    .map(|&row| members.iter().map(|&i| coefficient(row, i)).collect())
                    .collect();
                assert!(
                    invert(system).is_some(),
                    "rows {rows:?} members {members:?}"
                );
            }
        }
    }

    #[test]
    fn parity_rows_use_wire_indices_past_the_retired_scheme() {
        assert_eq!(rs_parity_row(0), None);
        assert_eq!(rs_parity_row(1), None);
        assert_eq!(rs_parity_row(RS_PARITY_INDEX_BASE), Some(0));
        assert_eq!(
            rs_parity_row(RS_PARITY_INDEX_BASE + MAX_PARITY_FRAMES as u32),
            None
        );
        let block = encode_block(
            vec![PendingMember {
                seq: 5,
                payload: Bytes::from_static(b"abc"),
                terminator: false,
            }],
            2,
        );
        let wire = proto::decode_voice(&block.encode(1, 2, 1).unwrap()).unwrap();
        assert!(wire.fec_parity);
        assert_eq!(wire.fec_parity_index, RS_PARITY_INDEX_BASE + 1);
        assert!(block.encode(1, 2, 2).is_none());
    }

    /// Push `seq` on a fixed stream and return the `(member_seqs, row,
    /// tail_step)` of every parity it made due.
    fn due(sender: &FecSenderState, seq: u64, terminator: bool) -> Vec<(Vec<u64>, usize, u32)> {
        sender
            .push(
                2,
                &[9],
                7,
                42,
                seq,
                Bytes::from(payload_for(seq)),
                terminator,
            )
            .into_iter()
            .map(|emission| {
                (
                    emission.member_seqs().to_vec(),
                    (emission.wire_index() - RS_PARITY_INDEX_BASE) as usize,
                    emission.tail_step,
                )
            })
            .collect()
    }

    #[test]
    fn sender_interleaves_frames_and_paces_each_blocks_rows_one_per_frame() {
        let sender = FecSenderState::new(3, 3, 2);
        let a = vec![0, 2, 4];
        let b = vec![1, 3, 5];
        let schedule: Vec<Vec<(Vec<u64>, usize, u32)>> =
            (0..8).map(|seq| due(&sender, seq, false)).collect();
        assert!(schedule[..4].iter().all(Vec::is_empty));
        // Block A completes at frame 4 and block B at frame 5; each sends one
        // row per data frame, so no two rows of one block leave together.
        assert_eq!(schedule[4], vec![(a.clone(), 0, 0)]);
        assert_eq!(schedule[5], vec![(a.clone(), 1, 0), (b.clone(), 0, 0)]);
        assert_eq!(schedule[6], vec![(a, 2, 0), (b.clone(), 1, 0)]);
        assert_eq!(schedule[7], vec![(b, 2, 0)]);
    }

    #[test]
    fn terminator_flushes_partial_blocks_and_paces_the_remaining_rows() {
        let sender = FecSenderState::new(4, 2, 2);
        for seq in 0..4 {
            assert!(due(&sender, seq, false).is_empty());
        }
        let tail = due(&sender, 4, true);
        assert_eq!(
            tail,
            vec![
                (vec![0, 2, 4], 0, 0),
                (vec![1, 3], 0, 0),
                (vec![0, 2, 4], 1, 1),
                (vec![1, 3], 1, 1),
            ]
        );
        assert!(
            due(&sender, 5, false).is_empty(),
            "nothing owed after the tail"
        );
        let terminator = FecSenderState::new(4, 2, 2)
            .push(2, &[9], 7, 42, 0, Bytes::from(payload_for(0)), true)
            .remove(0);
        assert_eq!(terminator.terminator_mask(), 1);
        assert_eq!(terminator.delay(), Duration::ZERO);
    }

    #[test]
    fn sender_windows_are_isolated_by_link_and_recipients() {
        let sender = FecSenderState::new(2, 1, 1);
        for (hop, dst, seq) in [(2, 9, 0), (3, 9, 1), (2, 10, 2)] {
            assert!(
                sender
                    .push(hop, &[dst], 7, 42, seq, Bytes::from_static(b"abcd"), false)
                    .is_empty()
            );
        }
        for (hop, dst, seq, members) in [
            (2, 9, 3, vec![0, 3]),
            (3, 9, 4, vec![1, 4]),
            (2, 10, 5, vec![2, 5]),
        ] {
            let emissions =
                sender.push(hop, &[dst], 7, 42, seq, Bytes::from_static(b"abcd"), false);
            assert_eq!(emissions.len(), 1);
            assert_eq!(emissions[0].member_seqs(), members);
        }
    }

    #[test]
    fn repeated_copy_does_not_duplicate_a_block_member() {
        let sender = FecSenderState::new(2, 1, 1);
        assert!(
            sender
                .push(2, &[9], 7, 42, 1, Bytes::from_static(b"ab"), false)
                .is_empty()
        );
        assert!(
            sender
                .push(2, &[9], 7, 42, 1, Bytes::from_static(b"ab"), false)
                .is_empty()
        );
        let emissions = sender.push(2, &[9], 7, 42, 2, Bytes::from_static(b"cdef"), false);
        assert_eq!(emissions[0].member_seqs(), vec![1, 2]);
    }

    #[test]
    fn parity_prefers_an_alternate_only_when_its_metrics_can_carry_it() {
        use shitspeak_s2s_transport::TransportKind;
        let primary = |loss| VoiceRouteQuality::new(2, TransportKind::Udp, 50_000, loss, 0);
        let with_alternate = |loss, alternate_loss, alternate_latency| {
            primary(loss).with_alternate_route_quality(
                3,
                alternate_latency,
                TransportKind::Udp,
                alternate_loss,
                0,
            )
        };
        // No alternate, or one without live metrics.
        assert!(!parity_alternate_usable(primary(0), false));
        assert!(!parity_alternate_usable(
            primary(0).with_alternate_route(3, 60_000),
            false
        ));
        // A clean or comparably lossy alternate carries parity.
        assert!(parity_alternate_usable(
            with_alternate(0, 10_000, 60_000),
            false
        ));
        assert!(parity_alternate_usable(
            with_alternate(200_000, 250_000, 60_000),
            false
        ));
        // The primary's datagram-lane loss counts as its loss.
        assert!(parity_alternate_usable(
            with_alternate(0, 250_000, 60_000).with_datagram_loss_ppm(Some(200_000)),
            false
        ));
        // Much lossier, too slow, or shedding alternates do not.
        assert!(!parity_alternate_usable(
            with_alternate(0, 50_000, 60_000),
            false
        ));
        assert!(!parity_alternate_usable(
            with_alternate(0, 0, 150_001),
            false
        ));
        assert!(!parity_alternate_usable(with_alternate(0, 0, 60_000), true));
    }

    #[test]
    fn receiver_recovers_variable_length_members_from_any_k_frames() {
        let payloads: Vec<Vec<u8>> = (10..14).map(payload_for).collect();
        let refs: Vec<&[u8]> = payloads.iter().map(Vec::as_slice).collect();
        let seqs: Vec<u64> = (10..14).collect();
        // Every loss pattern of at most `parity` members, with every choice of
        // surviving parity rows, recovers the originals.
        for lost_mask in 0u32..16 {
            let lost = lost_mask.count_ones() as usize;
            if lost == 0 || lost > 4 {
                continue;
            }
            for row_mask in 0u32..16 {
                if row_mask.count_ones() as usize != lost {
                    continue;
                }
                let mut mirror = ReceiverFecWindow::new(16, Instant::now());
                for (index, seq) in seqs.iter().enumerate() {
                    if lost_mask & (1 << index) == 0 {
                        mirror.record_frame(frame(*seq, refs[index], false));
                    }
                }
                if lost == 4 {
                    // No block member survives: metadata comes from a
                    // neighbouring mirrored frame.
                    mirror.record_frame(frame(9, b"neighbour", false));
                }
                for row in 0..4 {
                    if row_mask & (1 << row) != 0 {
                        mirror.record_parity(
                            seqs.clone(),
                            Bytes::from(rs_parity(&refs, row)),
                            row,
                            0,
                        );
                    }
                }
                let recovered = mirror.try_reconstruct(&any);
                assert_eq!(
                    recovered.len(),
                    lost,
                    "lost {lost_mask:04b} rows {row_mask:04b}"
                );
                for frame in recovered {
                    let index = (frame.s2s_seq - 10) as usize;
                    assert_eq!(frame.payload.as_ref(), refs[index]);
                }
            }
        }
    }

    #[test]
    fn receiver_needs_as_many_parities_as_missing_members() {
        let payloads: Vec<Vec<u8>> = (0..4).map(payload_for).collect();
        let refs: Vec<&[u8]> = payloads.iter().map(Vec::as_slice).collect();
        let mut mirror = ReceiverFecWindow::new(8, Instant::now());
        mirror.record_frame(frame(0, refs[0], false));
        mirror.record_frame(frame(1, refs[1], false));
        mirror.record_parity(vec![0, 1, 2, 3], Bytes::from(rs_parity(&refs, 1)), 1, 0);
        assert!(mirror.try_reconstruct(&any).is_empty());
        mirror.record_parity(vec![0, 1, 2, 3], Bytes::from(rs_parity(&refs, 3)), 3, 0);
        let recovered = mirror.try_reconstruct(&any);
        assert_eq!(recovered.len(), 2);
    }

    #[test]
    fn receiver_restores_terminator_flag_and_honours_wanted() {
        let payloads: Vec<Vec<u8>> = (1..=3).map(payload_for).collect();
        let refs: Vec<&[u8]> = payloads.iter().map(Vec::as_slice).collect();
        let mut mirror = ReceiverFecWindow::new(8, Instant::now());
        mirror.record_frame(frame(1, refs[0], false));
        mirror.record_parity(vec![1, 2, 3], Bytes::from(rs_parity(&refs, 0)), 0, 1 << 2);
        mirror.record_parity(vec![1, 2, 3], Bytes::from(rs_parity(&refs, 1)), 1, 1 << 2);
        // Seq 2 already reached the listener another way: only 3 is wanted.
        let recovered = mirror.try_reconstruct(&|seq| seq == 3);
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].s2s_seq, 3);
        assert!(recovered[0].is_terminator);
        assert_eq!(recovered[0].payload.as_ref(), refs[2]);
    }

    #[test]
    fn unwanted_reconstructions_wait_until_wanted_and_yield_to_their_original() {
        let payloads: Vec<Vec<u8>> = (1..=3).map(payload_for).collect();
        let refs: Vec<&[u8]> = payloads.iter().map(Vec::as_slice).collect();
        let mut mirror = ReceiverFecWindow::new(8, Instant::now());
        mirror.record_frame(frame(1, refs[0], false));
        mirror.record_parity(vec![1, 2, 3], Bytes::from(rs_parity(&refs, 0)), 0, 0);
        mirror.record_parity(vec![1, 2, 3], Bytes::from(rs_parity(&refs, 1)), 1, 0);
        // Only 2 is wanted now; 3 is solved in the same block but held back.
        let recovered = mirror.try_reconstruct(&|seq| seq == 2);
        assert_eq!(
            recovered.iter().map(|f| f.s2s_seq).collect::<Vec<_>>(),
            vec![2]
        );
        // 3 becomes a hole: the stashed reconstruction is released.
        let recovered = mirror.try_reconstruct(&|seq| seq == 3);
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].payload.as_ref(), refs[2]);
        assert!(mirror.try_reconstruct(&any).is_empty(), "released once");

        // An original that lands first discards its stashed reconstruction.
        let mut mirror = ReceiverFecWindow::new(8, Instant::now());
        mirror.record_frame(frame(1, refs[0], false));
        mirror.record_parity(vec![1, 2, 3], Bytes::from(rs_parity(&refs, 0)), 0, 0);
        mirror.record_parity(vec![1, 2, 3], Bytes::from(rs_parity(&refs, 1)), 1, 0);
        assert_eq!(mirror.try_reconstruct(&|seq| seq == 2).len(), 1);
        mirror.record_frame(frame(3, refs[2], false));
        assert!(mirror.try_reconstruct(&any).is_empty());
    }

    #[test]
    fn receiver_ignores_retired_parity_indices() {
        let state = ReceiverFecState::new(8);
        for wire_index in [0, 1] {
            assert!(!state.record_parity(
                7,
                11,
                vec![1, 2],
                Bytes::from_static(b"\0\x01z"),
                wire_index,
                0
            ));
        }
        assert!(state.try_reconstruct(7, 11, &any).is_empty());
    }

    /// Per-slot Gilbert-Elliott loss states for one path: every packet sent in
    /// a bad slot is lost, as congestion drops take back-to-back packets
    /// together. `avg` is the stationary loss rate and `mean_burst` the mean
    /// run of bad slots.
    fn burst_states(seed: u64, slots: usize, avg: f64, mean_burst: f64) -> Vec<bool> {
        let mut rng = XorShift(seed);
        let recover = 1.0 / mean_burst;
        let enter = avg * recover / (1.0 - avg);
        let mut bad = false;
        (0..slots)
            .map(|_| {
                let draw = rng.next_unit();
                bad = if bad { draw >= recover } else { draw < enter };
                bad
            })
            .collect()
    }

    /// Stream `frames` through a sender and a lossy network, one data frame per
    /// slot, returning `(raw data frames lost, frames still missing)`. Parity
    /// rides the alternate path when `diverse`, arrives `tail_step` slots
    /// late, and a reconstruction counts only within `deadline` slots of its
    /// frame. `lose(path, slot)` decides each packet's fate.
    fn simulate(
        block_size: usize,
        parity: usize,
        depth: usize,
        frames: u64,
        diverse: bool,
        deadline: u64,
        lose: impl FnMut(FecParityPath, u64) -> bool,
    ) -> (u64, u64) {
        simulate_code(
            FecSenderState::new(block_size, parity, depth),
            false,
            receiver_window_for(0, block_size, depth, 0),
            parity as u64,
            frames,
            diverse,
            deadline,
            lose,
        )
    }

    /// [`simulate`] for any code: `sliding` streams use the sender's
    /// sliding window, and `tail_slots` covers the parity paced after the
    /// final terminator.
    #[allow(clippy::too_many_arguments)]
    fn simulate_code(
        sender: FecSenderState,
        sliding: bool,
        receiver_window: usize,
        tail_slots: u64,
        frames: u64,
        diverse: bool,
        deadline: u64,
        mut lose: impl FnMut(FecParityPath, u64) -> bool,
    ) -> (u64, u64) {
        let receiver = ReceiverFecState::new(receiver_window);
        let mut delivered = std::collections::HashSet::new();
        let mut settled = std::collections::HashSet::new();
        let mut in_flight: std::collections::BTreeMap<u64, Vec<VoiceFrame>> = Default::default();
        let mut raw_lost = 0;
        let parity_path = if diverse {
            FecParityPath::Alternate
        } else {
            FecParityPath::Primary
        };
        let last_slot = frames + tail_slots + 1;
        for slot in 0..last_slot {
            if slot < frames {
                let seq = slot;
                let payload = payload_for(seq);
                let terminator = seq + 1 == frames;
                if lose(FecParityPath::Primary, slot) {
                    raw_lost += 1;
                } else {
                    delivered.insert(seq);
                    settled.insert(seq);
                    receiver.record_frame(frame(seq, &payload, terminator));
                }
                for emission in sender.push_with_code(
                    3,
                    &[9],
                    7,
                    11,
                    seq,
                    Bytes::from(payload),
                    terminator,
                    sliding,
                ) {
                    let arrival = slot + u64::from(emission.tail_step);
                    if lose(parity_path, arrival) {
                        continue;
                    }
                    let encoded = emission.encode(7, 11).unwrap();
                    in_flight
                        .entry(arrival)
                        .or_default()
                        .push(proto::decode_voice(&encoded).unwrap());
                }
            }
            for parity in in_flight.remove(&slot).unwrap_or_default() {
                receiver.record_parity(
                    7,
                    11,
                    parity.fec_member_seqs,
                    parity.payload,
                    parity.fec_parity_index,
                    parity.fec_terminator_mask,
                );
            }
            let unsettled = |candidate: u64| !settled.contains(&candidate);
            for recovered in receiver.try_reconstruct(7, 11, &unsettled) {
                assert_eq!(recovered.payload.as_ref(), payload_for(recovered.s2s_seq));
                settled.insert(recovered.s2s_seq);
                if slot - recovered.s2s_seq <= deadline {
                    delivered.insert(recovered.s2s_seq);
                }
            }
        }
        (raw_lost, frames - delivered.len() as u64)
    }

    #[test]
    fn default_code_holds_residual_loss_near_one_percent_at_twenty_percent_loss() {
        let frames = 60_000;
        let mut rng = XorShift(0x9E37_79B9_7F4A_7C15);
        let (raw_lost, residual) = simulate(3, 3, 2, frames, false, u64::MAX, |_, _| {
            rng.next_unit() < 0.20
        });
        let raw = raw_lost as f64 / frames as f64;
        let residual = residual as f64 / frames as f64;
        // Analytic residual for k=3, m=3 at 20% iid loss is 0.2 × P(≥3 of the
        // other 5 frames lost) ≈ 1.16%.
        assert!((0.19..0.21).contains(&raw), "raw loss {raw}");
        assert!(residual < 0.016, "residual loss {residual}");
    }

    #[test]
    fn paced_parity_survives_slot_correlated_loss() {
        // 20% loss where every packet of a slot shares its fate. Parity sent
        // back-to-back would die with its slot (≈ 9.7% residual); paced rows
        // land in independent slots.
        let frames = 60_000;
        let states = burst_states(0x5EED, frames as usize + 16, 0.20, 1.0);
        let (_, residual) = simulate(3, 3, 2, frames, false, 10, |_, slot| states[slot as usize]);
        let residual = residual as f64 / frames as f64;
        assert!(residual < 0.035, "residual loss {residual}");
    }

    #[test]
    fn alternate_path_parity_absorbs_long_bursts_on_the_data_path() {
        // Mean 4-slot bursts at 20% loss on the data path. Parity on the same
        // path leaves > 10% missing; an independent alternate path with the
        // same loss cuts that below 5%, and a clean alternate below 1%.
        let frames = 60_000;
        let slots = frames as usize + 16;
        let primary = burst_states(0xB0B, slots, 0.20, 4.0);
        let lossy_alternate = burst_states(0xA17, slots, 0.20, 4.0);
        let clean_alternate = burst_states(0xC1E, slots, 0.02, 4.0);
        let run = |diverse: bool, alternate: &[bool]| {
            let (raw, residual) = simulate(3, 3, 2, frames, diverse, 10, |path, slot| match path {
                FecParityPath::Primary | FecParityPath::Tree => primary[slot as usize],
                FecParityPath::Alternate => alternate[slot as usize],
            });
            (raw as f64 / frames as f64, residual as f64 / frames as f64)
        };
        let (raw, same_path) = run(false, &lossy_alternate);
        assert!((0.17..0.23).contains(&raw), "raw loss {raw}");
        assert!(same_path > 0.10, "same-path residual {same_path}");
        let (_, lossy) = run(true, &lossy_alternate);
        assert!(lossy < 0.05, "lossy-alternate residual {lossy}");
        let (_, clean) = run(true, &clean_alternate);
        assert!(clean < 0.01, "clean-alternate residual {clean}");
    }

    #[test]
    fn interleaved_alternate_parity_recovers_a_six_slot_outage() {
        // The data path drops everything in slots 6..12: six data frames and
        // any parity sent there. Parity on the alternate recovers all six.
        let (raw_lost, residual) = simulate(3, 3, 2, 24, true, u64::MAX, |path, slot| {
            path == FecParityPath::Primary && (6..12).contains(&slot)
        });
        assert_eq!(raw_lost, 6);
        assert_eq!(residual, 0);
        // On the data path itself the outage also takes the parity.
        let (_, same_path) = simulate(3, 3, 2, 24, false, u64::MAX, |_, slot| {
            (6..12).contains(&slot)
        });
        assert!(same_path > 0);
    }

    // ------------------------------------------------------------------
    // Sliding-window parity.

    /// What a sender emits for frames `0..frames` of one stream: per sent
    /// frame, the parity wire bodies it made due, in order.
    fn sent_parity(
        sender: &FecSenderState,
        frames: u64,
        terminator_at: Option<u64>,
        sliding: bool,
    ) -> Vec<Vec<VoiceFrame>> {
        (0..frames)
            .map(|seq| {
                sender
                    .push_with_code(
                        3,
                        &[9],
                        7,
                        11,
                        seq,
                        Bytes::from(payload_for(seq)),
                        terminator_at == Some(seq),
                        sliding,
                    )
                    .into_iter()
                    .map(|emission| proto::decode_voice(&emission.encode(7, 11).unwrap()).unwrap())
                    .collect()
            })
            .collect()
    }

    /// Feed a receiver the data frames and parity frames a lossy path kept.
    fn deliver(
        receiver: &ReceiverFecState,
        parity: &[Vec<VoiceFrame>],
        terminator_at: Option<u64>,
        data_kept: impl Fn(u64) -> bool,
        parity_kept: impl Fn(u64) -> bool,
    ) {
        for (seq, rows) in parity.iter().enumerate() {
            let seq = seq as u64;
            if data_kept(seq) {
                receiver.record_frame(frame(seq, &payload_for(seq), terminator_at == Some(seq)));
            }
            if parity_kept(seq) {
                for row in rows {
                    assert!(receiver.record_parity(
                        7,
                        11,
                        row.fec_member_seqs.clone(),
                        row.payload.clone(),
                        row.fec_parity_index,
                        row.fec_terminator_mask,
                    ));
                }
            }
        }
    }

    fn recovered_seqs(receiver: &ReceiverFecState) -> Vec<u64> {
        let recovered = receiver.try_reconstruct(7, 11, &any);
        for frame in &recovered {
            assert_eq!(
                frame.payload.as_ref(),
                payload_for(frame.s2s_seq).as_slice()
            );
        }
        recovered.iter().map(|frame| frame.s2s_seq).collect()
    }

    fn sliding_sender(window: usize) -> FecSenderState {
        FecSenderState::new(3, 3, 2).with_sliding_window(window)
    }

    #[test]
    fn sliding_parity_follows_every_frame_over_the_last_window_members() {
        let sent = sent_parity(&sliding_sender(4), 6, None, true);
        for (seq, rows) in sent.iter().enumerate() {
            let seq = seq as u64;
            assert_eq!(rows.len(), 1, "one equation per data frame");
            let first = seq.saturating_sub(3);
            assert_eq!(rows[0].fec_member_seqs, (first..=seq).collect::<Vec<_>>());
            assert_eq!(rows[0].fec_parity_index, SLIDING_PARITY_INDEX_BASE);
            assert_eq!(rows[0].s2s_seq, seq);
        }
        // Without the recipients' capability, or with the window off, the same
        // sender keeps the block code.
        let block = sent_parity(&sliding_sender(4), 6, None, false);
        let disabled = sent_parity(&sliding_sender(0), 6, None, true);
        for rows in block.iter().chain(&disabled).flatten() {
            assert!(rs_parity_row(rows.fec_parity_index).is_some());
        }
    }

    /// The point of the code: a single loss is solvable from the parity sent
    /// with the lost frame, before any later frame exists. The default block
    /// code cannot solve it until the frame's block completes.
    #[test]
    fn a_single_loss_is_recovered_from_the_parity_sent_with_it() {
        for lost in 0..6 {
            let sent = sent_parity(&sliding_sender(4), lost + 1, None, true);
            let receiver = ReceiverFecState::new(32);
            deliver(&receiver, &sent, None, |seq| seq != lost, |_| true);
            // Frame 0 has nothing earlier to copy routing metadata from.
            if lost > 0 {
                assert_eq!(recovered_seqs(&receiver), vec![lost], "lost {lost}");
            }
        }
        // The same loss under the default block code, with everything sent up
        // to and including the lost frame delivered, is not yet solvable: seq
        // 3 sits in the block {1, 3, 5}, whose first parity leaves with 5.
        let block = sent_parity(&FecSenderState::new(3, 3, 2), 4, None, false);
        let receiver = ReceiverFecState::new(32);
        deliver(&receiver, &block, None, |seq| seq != 3, |_| true);
        assert!(recovered_seqs(&receiver).is_empty());
    }

    #[test]
    fn a_burst_whose_parity_survives_is_recovered_jointly_at_its_last_frame() {
        for burst in 2..=6u64 {
            let first = 8;
            let last = first + burst - 1;
            let sent = sent_parity(&sliding_sender(4), last + 1, None, true);
            let receiver = ReceiverFecState::new(32);
            deliver(
                &receiver,
                &sent,
                None,
                |seq| !(first..=last).contains(&seq),
                |_| true,
            );
            // Each lost frame's own parity still covers it, and every newer
            // equation adds one unknown: the system is triangular.
            assert_eq!(
                recovered_seqs(&receiver),
                (first..=last).collect::<Vec<_>>(),
                "burst {burst}"
            );
        }
    }

    #[test]
    fn a_burst_that_takes_its_parity_too_is_recovered_up_to_window_minus_one() {
        let window = 4u64;
        for burst in 1..=window {
            let first = 8;
            let last = first + burst - 1;
            // Enough later frames for every equation that still covers the
            // burst to be sent.
            let sent = sent_parity(&sliding_sender(window as usize), last + window, None, true);
            let receiver = ReceiverFecState::new(32);
            let lost = |seq: u64| (first..=last).contains(&seq);
            deliver(&receiver, &sent, None, |seq| !lost(seq), |seq| !lost(seq));
            let recovered = recovered_seqs(&receiver);
            if burst < window {
                assert_eq!(
                    recovered,
                    (first..=last).collect::<Vec<_>>(),
                    "burst {burst}"
                );
            } else {
                // No surviving equation covers the burst's first frame. The
                // rest are pinned only if the equations determine them; none
                // is ever guessed.
                assert!(!recovered.contains(&first), "burst {burst}: {recovered:?}");
            }
        }
    }

    #[test]
    fn the_tail_after_a_terminator_recovers_the_final_window() {
        let sent = sent_parity(&sliding_sender(4), 4, Some(3), true);
        // With the terminator: its own equation plus three paced tail steps,
        // all over the final window.
        assert_eq!(
            sent[3]
                .iter()
                .map(|row| row.fec_parity_index - SLIDING_PARITY_INDEX_BASE)
                .collect::<Vec<_>>(),
            vec![0, 1, 2, 3]
        );
        let receiver = ReceiverFecState::new(32);
        // Frames 2 and 3 and the equations sent with them are lost; the tail
        // that follows the terminator survives.
        deliver(&receiver, &sent, Some(3), |seq| seq < 2, |seq| seq < 2);
        for row in &sent[3][1..] {
            receiver.record_parity(
                7,
                11,
                row.fec_member_seqs.clone(),
                row.payload.clone(),
                row.fec_parity_index,
                row.fec_terminator_mask,
            );
        }
        let recovered = receiver.try_reconstruct(7, 11, &any);
        assert_eq!(
            recovered
                .iter()
                .map(|frame| (frame.s2s_seq, frame.is_terminator))
                .collect::<Vec<_>>(),
            vec![(2, false), (3, true)]
        );
        // The next utterance starts a fresh window.
        let next = sliding_sender(4);
        sent_parity(&next, 4, Some(3), true);
        let after =
            next.push_with_code(3, &[9], 7, 11, 4, Bytes::from(payload_for(4)), false, true);
        assert_eq!(after[0].member_seqs(), vec![4]);
    }

    #[test]
    fn an_underdetermined_system_recovers_nothing() {
        let sent = sent_parity(&sliding_sender(4), 6, None, true);
        let receiver = ReceiverFecState::new(32);
        // 3 and 4 lost; only the equation sent with 5 survives, and it covers
        // both: one equation, two unknowns.
        deliver(
            &receiver,
            &sent,
            None,
            |seq| seq != 3 && seq != 4,
            |seq| seq == 5,
        );
        assert!(recovered_seqs(&receiver).is_empty());
    }

    #[test]
    fn sliding_recovery_honours_wanted_and_yields_to_the_original() {
        let sent = sent_parity(&sliding_sender(4), 5, None, true);
        let receiver = ReceiverFecState::new(32);
        deliver(&receiver, &sent, None, |seq| seq != 4, |_| true);
        // Nothing is wanted yet: solved but stashed.
        assert!(receiver.try_reconstruct(7, 11, &|_| false).is_empty());
        assert_eq!(recovered_seqs(&receiver), vec![4]);
    }

    #[test]
    fn block_only_and_sliding_wire_indices_never_overlap() {
        for step in 0..MAX_SLIDING_WINDOW as u32 {
            assert_eq!(rs_parity_row(SLIDING_PARITY_INDEX_BASE + step), None);
            assert_eq!(
                sliding_parity_step(SLIDING_PARITY_INDEX_BASE + step),
                Some(step)
            );
        }
        for row in 0..MAX_PARITY_FRAMES as u32 {
            assert_eq!(sliding_parity_step(RS_PARITY_INDEX_BASE + row), None);
        }
        assert_eq!(
            sliding_parity_step(SLIDING_PARITY_INDEX_BASE + MAX_SLIDING_WINDOW as u32),
            None
        );
    }

    /// The window the receiver mirrors covers two sliding windows.
    #[test]
    fn the_receiver_window_covers_the_sliding_window() {
        assert_eq!(receiver_window_for(0, 2, 1, 16), 32);
        assert_eq!(receiver_window_for(0, 2, 1, 64), 2 * MAX_SLIDING_WINDOW);
        assert_eq!(receiver_window_for(40, 3, 2, 4), 40);
    }

    /// The production condition: losses on the data path, parity on an
    /// independent alternate. "In time" is recovered in the very slot the
    /// frame was due — before the next frame arrives and the reorder
    /// releases past it. The block code makes only the member that completes
    /// its block in time (about a third of losses); the sliding window makes
    /// nearly all of them, at the same one-parity-per-frame overhead.
    #[test]
    fn sliding_parity_recovers_losses_before_the_release_where_blocks_cannot() {
        let frames = 60_000;
        let slots = frames as usize + 32;
        for (mean_burst, seed) in [(1.0, 0x51_1DE), (2.0, 0xB0_B5)] {
            let primary = burst_states(seed, slots, 0.02, mean_burst);
            let alternate = burst_states(seed ^ 0xA17, slots, 0.005, mean_burst);
            let lose = |path: FecParityPath, slot: u64| match path {
                FecParityPath::Primary | FecParityPath::Tree => primary[slot as usize],
                FecParityPath::Alternate => alternate[slot as usize],
            };
            let (raw, block) = simulate_code(
                FecSenderState::new(3, 3, 2),
                false,
                receiver_window_for(0, 3, 2, 0),
                3,
                frames,
                true,
                0,
                lose,
            );
            let (_, sliding) = simulate_code(
                FecSenderState::new(3, 3, 2).with_sliding_window(4),
                true,
                receiver_window_for(0, 3, 2, 4),
                4,
                frames,
                true,
                0,
                lose,
            );
            let raw = raw as f64 / frames as f64;
            let block = block as f64 / frames as f64;
            let sliding = sliding as f64 / frames as f64;
            assert!(
                (0.015..0.025).contains(&raw),
                "burst {mean_burst}: raw {raw}"
            );
            assert!(
                block > raw / 2.0,
                "burst {mean_burst}: block in time {block} of {raw}"
            );
            assert!(
                sliding < raw / 10.0,
                "burst {mean_burst}: sliding in time {sliding} of {raw} (block {block})"
            );
        }
    }

    /// Given time, the sliding window recovers at least as much as the
    /// default block code at its own overhead when the parity path is
    /// independent.
    #[test]
    fn sliding_parity_eventual_recovery_matches_the_block_code() {
        let frames = 60_000;
        let slots = frames as usize + 32;
        let primary = burst_states(0xD00D, slots, 0.05, 2.0);
        let alternate = burst_states(0xFEED, slots, 0.02, 2.0);
        let lose = |path: FecParityPath, slot: u64| match path {
            FecParityPath::Primary | FecParityPath::Tree => primary[slot as usize],
            FecParityPath::Alternate => alternate[slot as usize],
        };
        let (_, block) = simulate_code(
            FecSenderState::new(3, 3, 2),
            false,
            receiver_window_for(0, 3, 2, 0),
            3,
            frames,
            true,
            10,
            lose,
        );
        let (_, sliding) = simulate_code(
            FecSenderState::new(3, 3, 2).with_sliding_window(4),
            true,
            receiver_window_for(0, 3, 2, 4),
            4,
            frames,
            true,
            10,
            lose,
        );
        assert!(sliding <= block, "sliding {sliding} vs block {block}");
    }

    /// Frames can reach the sender out of order — proactive copies are sent
    /// from a queue. The equation's coefficients must not depend on push
    /// order: the receiver only sees the member seqs, so a sender keyed on
    /// the last-pushed member and a receiver keyed on the newest seq would
    /// disagree and rebuild garbage.
    #[test]
    fn sliding_parity_survives_out_of_order_pushes() {
        let sender = sliding_sender(4);
        let receiver = ReceiverFecState::new(32);
        let mut equations = Vec::new();
        for seq in [0u64, 1, 3, 2] {
            for emission in sender.push_with_code(
                3,
                &[9],
                7,
                11,
                seq,
                Bytes::from(payload_for(seq)),
                false,
                true,
            ) {
                equations.push(proto::decode_voice(&emission.encode(7, 11).unwrap()).unwrap());
            }
            if seq != 2 {
                receiver.record_frame(frame(seq, &payload_for(seq), false));
            }
        }
        // Only the equation sent with 2, the last one pushed, covers 2 alone
        // among unknowns.
        let last = equations.last().unwrap();
        assert!(receiver.record_parity(
            7,
            11,
            last.fec_member_seqs.clone(),
            last.payload.clone(),
            last.fec_parity_index,
            last.fec_terminator_mask,
        ));
        assert_eq!(recovered_seqs(&receiver), vec![2]);
    }
}
