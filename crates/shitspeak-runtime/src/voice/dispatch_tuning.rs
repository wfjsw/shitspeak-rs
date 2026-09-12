use std::{
    collections::HashMap,
    fmt,
    hint::black_box,
    net::SocketAddr,
    time::{Duration, Instant},
};

use bytes::Bytes;
use parking_lot::Mutex;
use rayon::prelude::*;
use shitspeak_client_crypto::CryptState;
use shitspeak_runtime_config::{VoiceDispatchMode, VoiceDispatchTuning};

use super::dispatch_cost::{CostModel, Sample};

use super::{
    codec::{Audio, AudioPayload, OpusPayload, PacketFormat},
    udp_batch::DatagramBatch,
};
use crate::{
    client::client_session_identifier::ClientSessionIdentifier,
    messages::encoder::{AudioContext, AudioTarget},
};

const PAYLOAD_CLASS_BOUNDARY_BYTES: usize = 512;
const CONSERVATIVE_FANOUT_THRESHOLD: usize = 512;
const CONSERVATIVE_RAYON_MIN_LEN: usize = 256;
const CALIBRATION_KEY: [u8; 16] = [0x42; 16];
const CALIBRATION_IV_E: [u8; 16] = [0x01; 16];
const CALIBRATION_IV_D: [u8; 16] = [0x02; 16];
const CALIBRATION_MAX_FANOUT: usize = 8192;
const CALIBRATION_LOW_FANOUTS: [usize; 7] = [8, 16, 32, 64, 128, 256, 512];
const CALIBRATION_VALIDATION_FANOUTS: [[usize; 5]; 2] =
    [[12, 24, 48, 96, 192], [384, 768, 1536, 3072, 6144]];
pub(crate) const MAX_RAYON_DISPATCH_BREAKPOINTS: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VoiceDispatchPlanSource {
    StartupCalibrated,
    Fixed,
    Sequential,
    Fallback,
}

impl VoiceDispatchPlanSource {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::StartupCalibrated => "startup_calibrated",
            Self::Fixed => "fixed",
            Self::Sequential => "sequential",
            Self::Fallback => "fallback",
        }
    }

    pub(crate) fn metric_value(self) -> u64 {
        match self {
            Self::StartupCalibrated => 0,
            Self::Fixed => 1,
            Self::Sequential => 2,
            Self::Fallback => 3,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct RayonDispatchBreakpoint {
    fanout_threshold: usize,
    rayon_max_workers: usize,
    rayon_min_len: usize,
}

impl RayonDispatchBreakpoint {
    pub(crate) const fn new(
        fanout_threshold: usize,
        rayon_max_workers: usize,
        rayon_min_len: usize,
    ) -> Self {
        Self {
            fanout_threshold,
            rayon_max_workers,
            rayon_min_len,
        }
    }

    const fn disabled() -> Self {
        Self::new(usize::MAX, 1, 1)
    }

    pub(crate) const fn fanout_threshold(self) -> usize {
        self.fanout_threshold
    }

    pub(crate) const fn rayon_max_workers(self) -> usize {
        // Expose the unbounded legacy profile as zero to telemetry rather than
        // publishing `usize::MAX` as an implausible worker count.
        if self.rayon_max_workers == usize::MAX {
            0
        } else {
            self.rayon_max_workers
        }
    }

    pub(crate) const fn rayon_min_len(self) -> usize {
        self.rayon_min_len
    }
}

impl fmt::Debug for RayonDispatchBreakpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let rayon_max_workers =
            (self.rayon_max_workers != usize::MAX).then_some(self.rayon_max_workers);
        formatter
            .debug_struct("RayonDispatchBreakpoint")
            .field("fanout_threshold", &self.fanout_threshold)
            .field("rayon_max_workers", &rayon_max_workers)
            .field("rayon_min_len", &self.rayon_min_len)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct VoiceDispatchProfile {
    model: Option<CostModel>,
    breakpoints: [RayonDispatchBreakpoint; MAX_RAYON_DISPATCH_BREAKPOINTS],
    breakpoint_count: usize,
}

impl VoiceDispatchProfile {
    const fn new(fanout_threshold: usize, rayon_min_len: usize) -> Self {
        Self {
            // The legacy fixed configuration has no worker cap. Its one tier
            // therefore preserves the old target-run-size behavior exactly.
            breakpoints: [RayonDispatchBreakpoint::new(fanout_threshold, usize::MAX, rayon_min_len);
                MAX_RAYON_DISPATCH_BREAKPOINTS],
            breakpoint_count: 1,
            model: None,
        }
    }

    const fn sequential_only() -> Self {
        Self {
            breakpoints: [RayonDispatchBreakpoint::disabled(); MAX_RAYON_DISPATCH_BREAKPOINTS],
            breakpoint_count: 0,
            model: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn from_breakpoints(breakpoints: &[RayonDispatchBreakpoint]) -> Option<Self> {
        if breakpoints.is_empty() || breakpoints.len() > MAX_RAYON_DISPATCH_BREAKPOINTS {
            return None;
        }
        if breakpoints.iter().any(|breakpoint| {
            breakpoint.fanout_threshold == 0
                || breakpoint.rayon_max_workers < 2
                || breakpoint.rayon_min_len == 0
        }) || breakpoints
            .windows(2)
            .any(|pair| pair[0].fanout_threshold >= pair[1].fanout_threshold)
        {
            return None;
        }

        let mut profile = Self::sequential_only();
        profile.breakpoints[..breakpoints.len()].copy_from_slice(breakpoints);
        profile.breakpoint_count = breakpoints.len();
        Some(profile)
    }

    fn from_model(model: CostModel) -> Self {
        let mut profile = Self::sequential_only();
        profile.model = Some(model);
        // These bounded summaries support existing telemetry. Dispatch itself
        // evaluates the fitted surface at the actual fanout, without rounding
        // to these entries or requiring a sustained win at all larger sizes.
        let mut previous = 1;
        for n in 1..=CALIBRATION_MAX_FANOUT {
            let partitions = model.choose(n, model.workers());
            if partitions != previous
                && partitions > 1
                && profile.breakpoint_count < MAX_RAYON_DISPATCH_BREAKPOINTS
            {
                profile.breakpoints[profile.breakpoint_count] =
                    RayonDispatchBreakpoint::new(n, partitions, n.div_ceil(partitions));
                profile.breakpoint_count += 1;
            }
            previous = partitions;
        }
        profile
    }

    pub(crate) fn uses_rayon(self, fanout: usize) -> bool {
        if let Some(model) = self.model {
            return model.choose(fanout, model.workers()) > 1;
        }
        self.breakpoint_for_fanout(fanout).is_some()
    }

    pub(crate) fn fanout_threshold(self) -> usize {
        self.breakpoints
            .first()
            .copied()
            .filter(|_| self.breakpoint_count > 0)
            .map_or(usize::MAX, RayonDispatchBreakpoint::fanout_threshold)
    }

    pub(crate) fn rayon_min_len(self) -> usize {
        self.breakpoints
            .first()
            .copied()
            .filter(|_| self.breakpoint_count > 0)
            .map_or(
                CONSERVATIVE_RAYON_MIN_LEN,
                RayonDispatchBreakpoint::rayon_min_len,
            )
    }

    pub(crate) fn breakpoints(&self) -> &[RayonDispatchBreakpoint] {
        &self.breakpoints[..self.breakpoint_count]
    }

    pub(crate) fn rayon_chunk_plan(self, fanout: usize, rayon_workers: usize) -> RayonChunkPlan {
        if let Some(model) = self.model {
            return RayonChunkPlan::with_chunk_count(
                fanout,
                model.choose(fanout, rayon_workers),
                rayon_workers,
            );
        }
        let breakpoint = self
            .breakpoint_for_fanout(fanout)
            .expect("Rayon dispatch requires a matching breakpoint");
        RayonChunkPlan::new(
            fanout,
            breakpoint.rayon_min_len,
            rayon_workers.min(breakpoint.rayon_max_workers),
        )
    }

    fn breakpoint_for_fanout(self, fanout: usize) -> Option<RayonDispatchBreakpoint> {
        self.breakpoints[..self.breakpoint_count]
            .iter()
            .rev()
            .find(|breakpoint| breakpoint.fanout_threshold <= fanout)
            .copied()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RayonChunkPlan {
    fanout: usize,
    chunk_count: usize,
    chunk_len: usize,
}

impl RayonChunkPlan {
    fn new(fanout: usize, target_chunk_len: usize, rayon_workers: usize) -> Self {
        assert!(fanout > 0, "Rayon chunking requires at least one recipient");
        assert!(
            target_chunk_len > 0,
            "Rayon chunking requires a nonzero target chunk length"
        );

        let requested_chunks = fanout.div_ceil(target_chunk_len);
        Self::with_chunk_count(fanout, requested_chunks, rayon_workers)
    }

    fn with_chunk_count(fanout: usize, requested_chunks: usize, rayon_workers: usize) -> Self {
        assert!(fanout > 0, "Rayon chunking requires at least one recipient");
        assert!(
            requested_chunks > 0,
            "Rayon chunking requires at least one requested chunk"
        );

        let chunk_count = requested_chunks.min(rayon_workers.max(1)).min(fanout);
        Self {
            fanout,
            chunk_count,
            chunk_len: fanout.div_ceil(chunk_count),
        }
    }

    pub(crate) const fn chunk_count(self) -> usize {
        self.chunk_count
    }

    #[cfg(test)]
    pub(crate) const fn chunk_len(self) -> usize {
        self.chunk_len
    }

    pub(crate) fn range(self, chunk_index: usize) -> std::ops::Range<usize> {
        assert!(
            chunk_index < self.chunk_count,
            "Rayon chunk index is in range"
        );
        let start = chunk_index * self.fanout / self.chunk_count;
        let end = (chunk_index + 1) * self.fanout / self.chunk_count;
        start..end
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct VoiceDispatchPlan {
    small_payload: VoiceDispatchProfile,
    large_payload: VoiceDispatchProfile,
    source: VoiceDispatchPlanSource,
}

impl VoiceDispatchPlan {
    pub(crate) const fn conservative() -> Self {
        Self {
            small_payload: VoiceDispatchProfile::new(
                CONSERVATIVE_FANOUT_THRESHOLD,
                CONSERVATIVE_RAYON_MIN_LEN,
            ),
            large_payload: VoiceDispatchProfile::new(
                CONSERVATIVE_FANOUT_THRESHOLD,
                CONSERVATIVE_RAYON_MIN_LEN,
            ),
            source: VoiceDispatchPlanSource::Fallback,
        }
    }

    fn sequential() -> Self {
        Self {
            small_payload: VoiceDispatchProfile::sequential_only(),
            large_payload: VoiceDispatchProfile::sequential_only(),
            source: VoiceDispatchPlanSource::Sequential,
        }
    }

    fn fixed(settings: &VoiceDispatchTuning) -> Self {
        let (small_threshold, small_min_len) = settings.small_payload_profile();
        let (large_threshold, large_min_len) = settings.large_payload_profile();
        Self {
            small_payload: VoiceDispatchProfile::new(small_threshold, small_min_len),
            large_payload: VoiceDispatchProfile::new(large_threshold, large_min_len),
            source: VoiceDispatchPlanSource::Fixed,
        }
    }

    fn calibrated(
        small_payload: VoiceDispatchProfile,
        large_payload: VoiceDispatchProfile,
    ) -> Self {
        Self {
            small_payload,
            large_payload,
            source: VoiceDispatchPlanSource::StartupCalibrated,
        }
    }

    pub(crate) fn for_payload_len(self, payload_len: usize) -> VoiceDispatchProfile {
        if payload_len <= PAYLOAD_CLASS_BOUNDARY_BYTES {
            self.small_payload
        } else {
            self.large_payload
        }
    }

    pub(crate) fn small_payload(self) -> VoiceDispatchProfile {
        self.small_payload
    }

    pub(crate) fn large_payload(self) -> VoiceDispatchProfile {
        self.large_payload
    }

    pub(crate) fn source(self) -> VoiceDispatchPlanSource {
        self.source
    }
}

pub(crate) struct ResolvedVoiceDispatchPlan {
    plan: VoiceDispatchPlan,
    elapsed: Duration,
    rayon_workers: usize,
}

impl ResolvedVoiceDispatchPlan {
    pub(crate) fn plan(&self) -> VoiceDispatchPlan {
        self.plan
    }

    pub(crate) fn elapsed(&self) -> Duration {
        self.elapsed
    }

    pub(crate) fn rayon_workers(&self) -> usize {
        self.rayon_workers
    }
}

pub(crate) async fn resolve_voice_dispatch_plan(
    settings: &VoiceDispatchTuning,
) -> Result<ResolvedVoiceDispatchPlan, std::io::Error> {
    settings
        .validate()
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;

    let started_at = Instant::now();
    let rayon_workers = rayon::current_num_threads();
    let plan = match settings.mode() {
        VoiceDispatchMode::Sequential => VoiceDispatchPlan::sequential(),
        VoiceDispatchMode::Fixed => VoiceDispatchPlan::fixed(settings),
        VoiceDispatchMode::StartupCalibrated if rayon_workers < 2 => {
            tracing::info!(
                rayon_workers,
                "voice dispatch calibration skipped because Rayon has fewer than two workers"
            );
            VoiceDispatchPlan::sequential()
        }
        VoiceDispatchMode::StartupCalibrated => {
            match calibrate_voice_dispatch_plan(rayon_workers).await {
                Ok(plan) => plan,
                Err(error) => {
                    tracing::warn!(
                        error = %error,
                        "voice dispatch calibration failed; using conservative fallback"
                    );
                    VoiceDispatchPlan::conservative()
                }
            }
        }
    };

    Ok(ResolvedVoiceDispatchPlan {
        plan,
        elapsed: started_at.elapsed(),
        rayon_workers,
    })
}

#[derive(Clone)]
struct CalibrationEncoded {
    bytes: Bytes,
    checksum: [u8; 16],
}

struct CalibrationRecipient {
    crypt: Mutex<Option<CryptState>>,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
}

struct CalibrationWorkload {
    recipients: Vec<CalibrationRecipient>,
}

// Shared by startup calibration and the standalone diagnostic report.
async fn calibrate_voice_dispatch_plan(rayon_workers: usize) -> Result<VoiceDispatchPlan, String> {
    let mut report = String::new();
    let small = calibrate_payload_profile(170, rayon_workers, &mut report).await?;
    let large = calibrate_payload_profile(768, rayon_workers, &mut report).await?;
    tracing::info!(report, "voice dispatch fitted cost models");
    Ok(VoiceDispatchPlan::calibrated(small, large))
}

async fn calibrate_payload_profile(
    opus_len: usize,
    workers: usize,
    report: &mut String,
) -> Result<VoiceDispatchProfile, String> {
    use std::fmt::Write;
    let started = Instant::now();
    let encoded = make_calibration_encoded(opus_len)?;
    let mut samples = Vec::new();
    for n in CALIBRATION_LOW_FANOUTS
        .into_iter()
        .chain([1024, 2048, 4096, CALIBRATION_MAX_FANOUT])
    {
        samples.extend(measure_surface(&encoded, n, workers, 7).await?);
    }
    let mut model = CostModel::fit(&samples, workers)?;
    // Independent fanouts test the selected action, including sequential,
    // against every available partition count. A poor selection contributes
    // additional training data instead of disabling Rayon at every fanout.
    for (round, fanouts) in CALIBRATION_VALIDATION_FANOUTS.into_iter().enumerate() {
        let mut validation = Vec::new();
        let mut worst_regret = 0.0_f64;
        for n in fanouts {
            let measured = measure_surface(&encoded, n, workers, 7).await?;
            worst_regret = worst_regret.max(report_choice(report, opus_len, model, &measured));
            validation.extend(measured);
        }
        writeln!(
            report,
            "validation opus={opus_len} round={round} worst_regret={worst_regret:.3}"
        )
        .unwrap();
        if worst_regret <= 0.10 {
            break;
        }
        samples.extend(validation);
        model = CostModel::fit(&samples, workers)?;
    }
    writeln!(report, "model opus={opus_len} {model:?}").unwrap();
    writeln!(
        report,
        "calibration opus={opus_len} elapsed_s={:.3}",
        started.elapsed().as_secs_f64()
    )
    .unwrap();
    Ok(VoiceDispatchProfile::from_model(model))
}

async fn measure_surface(
    encoded: &CalibrationEncoded,
    fanout: usize,
    workers: usize,
    samples: usize,
) -> Result<Vec<Sample>, String> {
    let workload = std::sync::Arc::new(make_workload(fanout)?);
    let count = workers.max(1).min(fanout);
    let mut timings = vec![Vec::with_capacity(samples); count];
    // Reuse each client's crypto state as production does. Setup and teardown
    // of clients are outside both timers. Rotate and shuffle candidate order
    // between rounds so the same candidate does not always get a warm pool.
    for round in 0..samples + 2 {
        let mut order: Vec<_> = (1..=count).collect();
        order.sort_by_key(|&p| {
            let mut x =
                (p as u64).wrapping_add((round as u64 + 1).wrapping_mul(0x9e3779b97f4a7c15));
            x = (x ^ (x >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
            x ^ (x >> 27)
        });
        for p in order {
            let elapsed = if p == 1 {
                time_sequential(&workload, encoded)
            } else {
                time_rayon(
                    workload.clone(),
                    encoded.clone(),
                    RayonChunkPlan::with_chunk_count(fanout, p, workers),
                )
                .await?
            };
            if round >= 2 {
                timings[p - 1].push(elapsed);
            }
        }
    }
    Ok(timings
        .into_iter()
        .enumerate()
        .map(|(p, mut times)| Sample {
            fanout,
            partitions: p + 1,
            micros: median_duration(&mut times).as_secs_f64() * 1e6,
        })
        .collect())
}

fn report_choice(
    report: &mut String,
    opus_len: usize,
    model: CostModel,
    measured: &[Sample],
) -> f64 {
    use std::fmt::Write;
    let n = measured[0].fanout;
    let chosen = model.choose(n, model.workers());
    let selected = measured.iter().find(|s| s.partitions == chosen).unwrap();
    let best = measured
        .iter()
        .min_by(|a, b| a.micros.total_cmp(&b.micros))
        .unwrap();
    let seq = measured.iter().find(|s| s.partitions == 1).unwrap();
    let regret = (selected.micros / best.micros - 1.0).max(0.0);
    writeln!(report, "opus={opus_len} listeners={n} selected={chosen} predicted_us={:.2} actual_us={:.2} sequential_us={:.2} measured_best={} best_us={:.2} regret={:.3}",
        model.predict(n, chosen), selected.micros, seq.micros, best.partitions, best.micros, regret).unwrap();
    regret
}

/// Runs the same model fitting and dispatch policy as startup, followed by an
/// independent partition sweep. It does not start listeners or a server.
#[doc(hidden)]
pub async fn voice_dispatch_benchmark_report() -> Result<String, String> {
    use std::fmt::Write;
    let started = Instant::now();
    let workers = rayon::current_num_threads();
    let mut report = format!("voice dispatch cost model: rayon_workers={workers}\n");
    if workers < 2 {
        writeln!(report, "sequential only: fewer than two Rayon workers").unwrap();
        return Ok(report);
    }
    let calibration_started = Instant::now();
    let small = calibrate_payload_profile(170, workers, &mut report).await?;
    let large = calibrate_payload_profile(768, workers, &mut report).await?;
    writeln!(
        report,
        "startup_calibration_elapsed_s={:.3}",
        calibration_started.elapsed().as_secs_f64()
    )
    .unwrap();
    for (opus_len, profile) in [(170, small), (768, large)] {
        let encoded = make_calibration_encoded(opus_len)?;
        for n in [
            8, 16, 24, 32, 40, 64, 128, 192, 256, 512, 1024, 2048, 4096, 8192,
        ] {
            let measured = measure_surface(&encoded, n, workers, 11).await?;
            report_choice(&mut report, opus_len, profile.model.unwrap(), &measured);
            write!(report, "candidates opus={opus_len} listeners={n}").unwrap();
            for sample in measured {
                write!(report, " {}:{:.2}", sample.partitions, sample.micros).unwrap();
            }
            writeln!(report).unwrap();
        }
    }
    writeln!(
        report,
        "benchmark_elapsed_s={:.3}",
        started.elapsed().as_secs_f64()
    )
    .unwrap();
    Ok(report)
}

fn time_sequential(workload: &CalibrationWorkload, encoded: &CalibrationEncoded) -> Duration {
    let started_at = Instant::now();
    let mut batches = HashMap::<SocketAddr, DatagramBatch>::new();
    if let Some(recipient) = workload.recipients.first() {
        batches.insert(
            recipient.local_addr,
            DatagramBatch::with_capacity(workload.recipients.len()),
        );
    }
    for recipient in &workload.recipients {
        encrypt_recipient(&mut batches, recipient, encoded);
    }
    let elapsed = started_at.elapsed();
    black_box(batches);
    elapsed
}

async fn time_rayon(
    workload: std::sync::Arc<CalibrationWorkload>,
    encoded: CalibrationEncoded,
    chunk_plan: RayonChunkPlan,
) -> Result<Duration, String> {
    let started_at = Instant::now();
    let batches = tokio::task::spawn_blocking(move || {
        let recipients = workload.recipients.as_slice();
        (0..chunk_plan.chunk_count())
            .into_par_iter()
            .map(|chunk_index| {
                let mut batches = HashMap::<SocketAddr, DatagramBatch>::new();
                for recipient in &recipients[chunk_plan.range(chunk_index)] {
                    encrypt_recipient(&mut batches, recipient, &encoded);
                }
                batches
            })
            .reduce(HashMap::new, |mut left, right| {
                for (local_addr, batch) in right {
                    left.entry(local_addr)
                        .or_insert_with(DatagramBatch::new)
                        .append(batch);
                }
                left
            })
    })
    .await
    .map_err(|error| format!("Rayon calibration task join error: {error}"))?;
    let elapsed = started_at.elapsed();
    black_box(batches);
    Ok(elapsed)
}

fn encrypt_recipient(
    batches: &mut HashMap<SocketAddr, DatagramBatch>,
    recipient: &CalibrationRecipient,
    encoded: &CalibrationEncoded,
) {
    let mut crypt = recipient
        .crypt
        .try_lock_until(Instant::now() + Duration::from_millis(10))
        .expect("calibration recipient has no concurrent sender");
    let state = crypt.as_mut().expect("calibration crypto state exists");

    let encrypted_len = encoded.bytes.len() + state.overhead();
    let batch = batches
        .entry(recipient.local_addr)
        .or_insert_with(DatagramBatch::new);
    batch
        .try_push_zeroed(recipient.remote_addr, encrypted_len, |buffer| {
            state.encrypt_with_precomputed_checksum(buffer, &encoded.bytes, &encoded.checksum)
        })
        .expect("calibration encrypts every recipient");
}

fn make_workload(fanout: usize) -> Result<CalibrationWorkload, String> {
    let local_addr = SocketAddr::from(([127, 0, 0, 1], 64738));
    let recipients = (0..fanout)
        .map(|index| {
            let port = 20_000_u16
                .checked_add(index as u16)
                .ok_or_else(|| "calibration recipient port overflow".to_owned())?;
            Ok(CalibrationRecipient {
                crypt: Mutex::new(Some(make_crypt_state()?)),
                local_addr,
                remote_addr: SocketAddr::from(([127, 0, 0, 1], port)),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(CalibrationWorkload { recipients })
}

fn make_crypt_state() -> Result<CryptState, String> {
    CryptState::from_key(
        "OCB2-AES128",
        &CALIBRATION_KEY,
        &CALIBRATION_IV_E,
        &CALIBRATION_IV_D,
    )
    .map_err(|error| format!("calibration crypt state setup failed: {error}"))
}

fn make_calibration_encoded(opus_len: usize) -> Result<CalibrationEncoded, String> {
    let audio = Audio {
        target: AudioTarget::Normal,
        sender_session: Some(ClientSessionIdentifier::from(12_345)),
        frame_number: 1000,
        audio_payload: AudioPayload::Opus(OpusPayload {
            frame: Bytes::from(vec![0xAB; opus_len]),
            is_terminator: false,
        }),
        positional_data: None,
        volume_adjustment: 1.0,
        format: PacketFormat::Legacy,
    };
    let bytes = Audio::encode(&audio, AudioContext::Normal, PacketFormat::Legacy);
    if (opus_len <= PAYLOAD_CLASS_BOUNDARY_BYTES)
        != (audio.audio_payload.len() <= PAYLOAD_CLASS_BOUNDARY_BYTES)
    {
        return Err("calibration payload class is inconsistent".to_owned());
    }
    Ok(CalibrationEncoded {
        checksum: CryptState::compute_plaintext_checksum(&bytes),
        bytes,
    })
}

fn median_duration(samples: &mut [Duration]) -> Duration {
    samples.sort_unstable();
    samples[samples.len() / 2]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optimizer_can_choose_five_partitions_for_2048_listeners() {
        let samples: Vec<_> = [64, 128, 256, 512, 1024, 2048, 4096, 8192]
            .into_iter()
            .flat_map(|n| {
                (1..=40).map(move |p| Sample {
                    fanout: n,
                    partitions: p,
                    micros: if p == 1 {
                        0.5 * n as f64
                    } else {
                        50.0 + 8.192 * p as f64 + 0.1 * n as f64 / p as f64
                    },
                })
            })
            .collect();
        let profile = VoiceDispatchProfile::from_model(CostModel::fit(&samples, 40).unwrap());
        assert!(!profile.uses_rayon(64));
        assert_eq!(profile.rayon_chunk_plan(2048, 40).chunk_count(), 5);
        assert_eq!(profile.rayon_chunk_plan(4096, 40).chunk_count(), 7);
        assert_eq!(profile.rayon_chunk_plan(8192, 3).chunk_count(), 3);
    }
    #[test]
    fn caps_explicit_chunks_at_the_rayon_worker_count() {
        let cases = [
            (40, 32, 8, 2, 20),
            (60, 32, 8, 2, 30),
            (2_048, 32, 8, 8, 256),
            (5, 1, 8, 5, 1),
        ];

        for (fanout, target_chunk_len, rayon_workers, expected_chunks, expected_chunk_len) in cases
        {
            let plan = RayonChunkPlan::new(fanout, target_chunk_len, rayon_workers);
            assert_eq!(plan.chunk_count(), expected_chunks);
            assert_eq!(plan.chunk_len(), expected_chunk_len);
            assert!(plan.chunk_count() <= rayon_workers);
            assert_eq!(
                (0..plan.chunk_count())
                    .map(|index| plan.range(index).len())
                    .sum::<usize>(),
                fanout
            );
        }
    }

    #[test]
    fn supports_exact_balanced_chunks_when_worker_count_is_large() {
        let plan = RayonChunkPlan::new(2_048, 16, 127);
        assert_eq!(plan.chunk_count(), 127);
        assert_eq!(plan.chunk_len(), 17);
        assert!(
            (0..plan.chunk_count())
                .map(|index| plan.range(index).len())
                .all(|len| len == 16 || len == 17)
        );
    }

    #[test]
    fn calibrated_breakpoints_scale_worker_count_and_batch_size_together() {
        let profile = VoiceDispatchProfile::from_breakpoints(&[
            RayonDispatchBreakpoint::new(512, 2, 256),
            RayonDispatchBreakpoint::new(1_024, 2, 512),
            RayonDispatchBreakpoint::new(1_536, 3, 512),
            RayonDispatchBreakpoint::new(2_048, 4, 512),
        ])
        .expect("valid calibrated breakpoint schedule");

        assert!(!profile.uses_rayon(511));
        assert_eq!(profile.rayon_chunk_plan(512, 8).chunk_count(), 2);
        assert_eq!(profile.rayon_chunk_plan(512, 8).chunk_len(), 256);
        assert_eq!(profile.rayon_chunk_plan(1_024, 8).chunk_count(), 2);
        assert_eq!(profile.rayon_chunk_plan(1_024, 8).chunk_len(), 512);
        assert_eq!(profile.rayon_chunk_plan(1_536, 8).chunk_count(), 3);
        assert_eq!(profile.rayon_chunk_plan(1_536, 8).chunk_len(), 512);
        assert_eq!(profile.rayon_chunk_plan(2_048, 8).chunk_count(), 4);
        assert_eq!(profile.rayon_chunk_plan(2_048, 8).chunk_len(), 512);
    }

    #[test]
    fn calibrated_breakpoints_cap_requested_workers_to_the_runtime_pool() {
        let profile =
            VoiceDispatchProfile::from_breakpoints(&[RayonDispatchBreakpoint::new(512, 8, 256)])
                .expect("valid calibrated breakpoint schedule");

        let plan = profile.rayon_chunk_plan(2_048, 4);
        assert_eq!(plan.chunk_count(), 4);
        assert_eq!(plan.chunk_len(), 512);
    }

    #[test]
    fn classifies_payload_boundary() {
        let plan = VoiceDispatchPlan::calibrated(
            VoiceDispatchProfile::new(64, 64),
            VoiceDispatchProfile::new(128, 128),
        );

        assert_eq!(plan.for_payload_len(512), VoiceDispatchProfile::new(64, 64));
        assert_eq!(
            plan.for_payload_len(513),
            VoiceDispatchProfile::new(128, 128)
        );
    }

    #[tokio::test]
    async fn startup_calibration_resolves_a_usable_plan() {
        let resolved = resolve_voice_dispatch_plan(&VoiceDispatchTuning::default())
            .await
            .expect("startup calibration resolves");
        let plan = resolved.plan();

        assert!(plan.small_payload().rayon_min_len() > 0);
        assert!(plan.large_payload().rayon_min_len() > 0);
        assert!(matches!(
            plan.source(),
            VoiceDispatchPlanSource::StartupCalibrated | VoiceDispatchPlanSource::Sequential
        ));
    }
}
