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
const MIN_MODELED_FANOUT: usize = CONSERVATIVE_FANOUT_THRESHOLD / 2;
const CONSERVATIVE_RAYON_MIN_LEN: usize = 256;
const CALIBRATION_KEY: [u8; 16] = [0x42; 16];
const CALIBRATION_IV_E: [u8; 16] = [0x01; 16];
const CALIBRATION_IV_D: [u8; 16] = [0x02; 16];
const CALIBRATION_MAX_FANOUT: usize = 2048;
const CALIBRATION_TARGET_CHUNK_LENS: [usize; 9] = [8, 16, 24, 32, 48, 64, 128, 256, 512];
pub(crate) const MAX_RAYON_DISPATCH_BREAKPOINTS: usize = 8;
const MODEL_CALIBRATION_WARMUPS: usize = 1;
const MODEL_CALIBRATION_SAMPLES: usize = 7;
const CONFIRMATION_WARMUPS: usize = 1;
const CONFIRMATION_SAMPLES: usize = 7;
const MODEL_MAX_RELATIVE_ERROR: f64 = 0.25;
const RAYON_WIN_PERCENT: u128 = 95;

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct VoiceDispatchProfile {
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
        }
    }

    const fn sequential_only() -> Self {
        Self {
            breakpoints: [RayonDispatchBreakpoint::disabled(); MAX_RAYON_DISPATCH_BREAKPOINTS],
            breakpoint_count: 0,
        }
    }

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

    pub(crate) fn uses_rayon(self, fanout: usize) -> bool {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

#[derive(Clone, Copy)]
struct CalibrationTiming {
    sequential: Duration,
    rayon: Duration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ModelProbe {
    fanout: usize,
    requested_chunks: usize,
}

impl ModelProbe {
    fn chunk_plan(self, rayon_workers: usize) -> RayonChunkPlan {
        RayonChunkPlan::with_chunk_count(self.fanout, self.requested_chunks, rayon_workers)
    }
}

#[derive(Clone, Copy)]
struct ModelMeasurement {
    fanout: usize,
    chunk_plan: RayonChunkPlan,
    timing: CalibrationTiming,
}

#[derive(Clone, Copy, Debug)]
struct LinearCostModel {
    fixed_ns: f64,
    per_recipient_ns: f64,
}

impl LinearCostModel {
    fn predict(self, fanout: usize) -> f64 {
        self.fixed_ns + self.per_recipient_ns * fanout as f64
    }
}

#[derive(Clone, Copy, Debug)]
enum RayonCostModel {
    TwoWorkers(LinearCostModel),
    General {
        dispatch_ns: f64,
        per_chunk_ns: f64,
        per_merged_recipient_ns: f64,
        critical_chunk_recipient_ns: f64,
        // Captures the way partitioning overhead changes with the critical
        // chunk length instead of forcing both effects into independent terms.
        chunk_critical_path_interaction_ns: f64,
    },
}

impl RayonCostModel {
    fn predict(self, chunk_plan: RayonChunkPlan) -> f64 {
        match self {
            Self::TwoWorkers(model) => model.predict(chunk_plan.fanout),
            Self::General {
                dispatch_ns,
                per_chunk_ns,
                per_merged_recipient_ns,
                critical_chunk_recipient_ns,
                chunk_critical_path_interaction_ns,
            } => {
                dispatch_ns
                    + per_chunk_ns * chunk_plan.chunk_count() as f64
                    + per_merged_recipient_ns * chunk_plan.fanout as f64
                    + critical_chunk_recipient_ns * chunk_plan.chunk_len() as f64
                    + chunk_critical_path_interaction_ns * chunk_plan.chunk_count() as f64
                        / chunk_plan.chunk_len() as f64
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ModeledDispatchTier {
    rayon_max_workers: usize,
    rayon_min_len: usize,
}

impl ModeledDispatchTier {
    fn chunk_plan(self, fanout: usize, rayon_workers: usize) -> RayonChunkPlan {
        RayonChunkPlan::new(
            fanout,
            self.rayon_min_len,
            rayon_workers.min(self.rayon_max_workers),
        )
    }
}

#[derive(Clone, Copy)]
struct ModeledProfileCandidate {
    profile: VoiceDispatchProfile,
}

#[derive(Clone, Copy)]
struct ModeledScheduleSegment {
    start_fanout: usize,
    end_fanout: usize,
    tier: ModeledDispatchTier,
    score: f64,
}

async fn calibrate_voice_dispatch_plan(rayon_workers: usize) -> Result<VoiceDispatchPlan, String> {
    let small_payload = make_calibration_encoded(170)?;
    let large_payload = make_calibration_encoded(768)?;
    let small_profile = calibrate_payload_profile("small", &small_payload, rayon_workers).await?;
    let large_profile = calibrate_payload_profile("large", &large_payload, rayon_workers).await?;

    Ok(VoiceDispatchPlan::calibrated(small_profile, large_profile))
}

async fn calibrate_payload_profile(
    payload_class: &'static str,
    encoded: &CalibrationEncoded,
    rayon_workers: usize,
) -> Result<VoiceDispatchProfile, String> {
    let mut measurements = Vec::new();
    for probe in model_training_probes(rayon_workers) {
        let chunk_plan = probe.chunk_plan(rayon_workers);
        let timing = measure_median_pair(
            encoded,
            probe.fanout,
            chunk_plan,
            MODEL_CALIBRATION_WARMUPS,
            MODEL_CALIBRATION_SAMPLES,
        )
        .await?;
        measurements.push(ModelMeasurement {
            fanout: probe.fanout,
            chunk_plan,
            timing,
        });
    }

    let sequential_model = match fit_sequential_model(&measurements) {
        Ok(model) => model,
        Err(reason) => {
            tracing::info!(
                payload_class,
                reason,
                "voice dispatch sequential model rejected; selecting sequential dispatch"
            );
            return Ok(VoiceDispatchProfile::sequential_only());
        }
    };
    let rayon_model = match fit_rayon_model(&measurements, rayon_workers) {
        Ok(model) => model,
        Err(reason) => {
            tracing::info!(
                payload_class,
                reason,
                sequential_model = ?sequential_model,
                "voice dispatch Rayon model rejected; selecting sequential dispatch"
            );
            return Ok(VoiceDispatchProfile::sequential_only());
        }
    };
    tracing::info!(
        payload_class,
        sequential_model = ?sequential_model,
        rayon_model = ?rayon_model,
        "voice dispatch calibration models fitted"
    );

    let holdout_probe = model_holdout_probe(rayon_workers);
    let holdout_plan = holdout_probe.chunk_plan(rayon_workers);
    let holdout = measure_median_pair(
        encoded,
        holdout_probe.fanout,
        holdout_plan,
        MODEL_CALIBRATION_WARMUPS,
        MODEL_CALIBRATION_SAMPLES,
    )
    .await?;
    if !model_matches_holdout(sequential_model, rayon_model, holdout_plan, holdout) {
        tracing::info!(
            payload_class,
            reason = "holdout_prediction_mismatch",
            sequential_model = ?sequential_model,
            rayon_model = ?rayon_model,
            holdout_fanout = holdout_probe.fanout,
            holdout_sequential_ns = holdout.sequential.as_nanos() as u64,
            predicted_sequential_ns = sequential_model.predict(holdout_probe.fanout),
            holdout_rayon_ns = holdout.rayon.as_nanos() as u64,
            predicted_rayon_ns = rayon_model.predict(holdout_plan),
            "voice dispatch model rejected; selecting sequential dispatch"
        );
        return Ok(VoiceDispatchProfile::sequential_only());
    }

    let Some(candidate) = select_modeled_profile(sequential_model, rayon_model, rayon_workers)
    else {
        tracing::info!(
            payload_class,
            reason = "no_sustained_modeled_rayon_win",
            sequential_model = ?sequential_model,
            rayon_model = ?rayon_model,
            "voice dispatch model found no sustained Rayon crossover; selecting sequential dispatch"
        );
        return Ok(VoiceDispatchProfile::sequential_only());
    };

    match confirm_modeled_profile(encoded, candidate, rayon_workers).await {
        Ok(()) => Ok(candidate.profile),
        Err(reason) => {
            tracing::info!(
                payload_class,
                reason,
                sequential_model = ?sequential_model,
                rayon_model = ?rayon_model,
                "voice dispatch model confirmation rejected; selecting sequential dispatch"
            );
            Ok(VoiceDispatchProfile::sequential_only())
        }
    }
}

fn model_training_probes(rayon_workers: usize) -> Vec<ModelProbe> {
    if rayon_workers == 2 {
        return vec![
            ModelProbe {
                fanout: 64,
                requested_chunks: 2,
            },
            ModelProbe {
                fanout: 512,
                requested_chunks: 2,
            },
            ModelProbe {
                fanout: CALIBRATION_MAX_FANOUT,
                requested_chunks: 2,
            },
        ];
    }

    let coarse_chunks = rayon_workers.min(4);
    let mut probes = Vec::new();
    for (fanout, requested_chunks) in [
        (64, 1),
        (64, 2),
        (512, 2),
        (512, coarse_chunks),
        (CALIBRATION_MAX_FANOUT, 2),
        (CALIBRATION_MAX_FANOUT, coarse_chunks),
        // The wide-pool shape must be part of the training set. Previously a
        // pool with more than four workers was asked to predict this unseen
        // shape only in the holdout, which made the model extrapolate exactly
        // where dispatch overhead is most sensitive.
        (512, rayon_workers),
        (CALIBRATION_MAX_FANOUT, rayon_workers),
    ] {
        let probe = ModelProbe {
            fanout,
            requested_chunks,
        };
        if !probes.contains(&probe) {
            probes.push(probe);
        }
    }
    probes
}

fn model_holdout_probe(rayon_workers: usize) -> ModelProbe {
    // Keep the full-pool shape independent of training while retaining a
    // fanout between the two full-pool training probes.
    ModelProbe {
        fanout: 1024,
        requested_chunks: rayon_workers,
    }
}

async fn measure_median_pair(
    encoded: &CalibrationEncoded,
    fanout: usize,
    chunk_plan: RayonChunkPlan,
    warmups: usize,
    samples: usize,
) -> Result<CalibrationTiming, String> {
    for warmup in 0..warmups {
        let _ = measure_pair(encoded, fanout, chunk_plan, warmup % 2 == 0).await?;
    }

    let mut sequential = Vec::with_capacity(samples);
    let mut rayon = Vec::with_capacity(samples);
    for sample in 0..samples {
        let timing = measure_pair(encoded, fanout, chunk_plan, sample % 2 == 0).await?;
        sequential.push(timing.sequential);
        rayon.push(timing.rayon);
    }

    Ok(CalibrationTiming {
        sequential: median_duration(&mut sequential),
        rayon: median_duration(&mut rayon),
    })
}

async fn measure_pair(
    encoded: &CalibrationEncoded,
    fanout: usize,
    chunk_plan: RayonChunkPlan,
    rayon_first: bool,
) -> Result<CalibrationTiming, String> {
    let sequential_work = make_workload(fanout)?;
    let rayon_work = make_workload(fanout)?;

    if rayon_first {
        let rayon = time_rayon(rayon_work, encoded.clone(), chunk_plan).await?;
        let sequential = time_sequential(sequential_work, encoded);
        Ok(CalibrationTiming { sequential, rayon })
    } else {
        let sequential = time_sequential(sequential_work, encoded);
        let rayon = time_rayon(rayon_work, encoded.clone(), chunk_plan).await?;
        Ok(CalibrationTiming { sequential, rayon })
    }
}

fn time_sequential(workload: CalibrationWorkload, encoded: &CalibrationEncoded) -> Duration {
    let started_at = Instant::now();
    let mut batches = HashMap::<SocketAddr, DatagramBatch>::new();
    for recipient in &workload.recipients {
        encrypt_recipient(&mut batches, recipient, encoded);
    }
    black_box(batches);
    started_at.elapsed()
}

async fn time_rayon(
    workload: CalibrationWorkload,
    encoded: CalibrationEncoded,
    chunk_plan: RayonChunkPlan,
) -> Result<Duration, String> {
    let started_at = Instant::now();
    tokio::task::spawn_blocking(move || {
        let recipients = workload.recipients.as_slice();
        let batches = (0..chunk_plan.chunk_count())
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
            });
        black_box(batches);
    })
    .await
    .map_err(|error| format!("Rayon calibration task join error: {error}"))?;
    Ok(started_at.elapsed())
}

fn encrypt_recipient(
    batches: &mut HashMap<SocketAddr, DatagramBatch>,
    recipient: &CalibrationRecipient,
    encoded: &CalibrationEncoded,
) {
    let Some(mut crypt) = recipient
        .crypt
        .try_lock_until(Instant::now() + Duration::from_millis(10))
    else {
        return;
    };
    let Some(state) = crypt.as_mut() else {
        return;
    };

    let encrypted_len = encoded.bytes.len() + state.overhead();
    let batch = batches
        .entry(recipient.local_addr)
        .or_insert_with(DatagramBatch::new);
    let _ = batch.try_push_zeroed(recipient.remote_addr, encrypted_len, |buffer| {
        state.encrypt_with_precomputed_checksum(buffer, &encoded.bytes, &encoded.checksum)
    });
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

fn fit_sequential_model(measurements: &[ModelMeasurement]) -> Result<LinearCostModel, String> {
    let mut samples_by_fanout = HashMap::<usize, Vec<f64>>::new();
    for measurement in measurements {
        samples_by_fanout
            .entry(measurement.fanout)
            .or_default()
            .push(duration_ns(measurement.timing.sequential));
    }
    let mut points = samples_by_fanout
        .into_iter()
        .map(|(fanout, mut samples)| {
            samples.sort_by(f64::total_cmp);
            (fanout as f64, samples[samples.len() / 2])
        })
        .collect::<Vec<_>>();
    points.sort_by(|left, right| left.0.total_cmp(&right.0));
    let model = fit_linear_model(&points)
        .or_else(|| {
            // Scheduler noise can invert the least-squares slope even when the
            // fanout medians are monotonically increasing. In that case retain
            // the observed monotonic trend and fit a conservative origin model.
            let increasing = points
                .first()
                .zip(points.last())
                .is_some_and(|(first, last)| last.1 > first.1);
            increasing.then(|| {
                let slope = points
                    .iter()
                    .map(|(fanout, duration)| fanout * duration)
                    .sum::<f64>()
                    / points
                        .iter()
                        .map(|(fanout, _)| fanout * fanout)
                        .sum::<f64>();
                LinearCostModel {
                    fixed_ns: 0.0,
                    per_recipient_ns: slope,
                }
            })
        })
        .ok_or_else(|| "invalid sequential linear fit".to_owned())?;
    if points
        .iter()
        .all(|(fanout, observed)| prediction_matches(model.predict(*fanout as usize), *observed))
    {
        Ok(model)
    } else {
        Err("sequential training prediction exceeded 25% error".to_owned())
    }
}

fn fit_rayon_model(
    measurements: &[ModelMeasurement],
    rayon_workers: usize,
) -> Result<RayonCostModel, String> {
    if rayon_workers == 2 {
        let points = measurements
            .iter()
            .filter(|measurement| measurement.chunk_plan.chunk_count() == 2)
            .map(|measurement| {
                (
                    measurement.fanout as f64,
                    duration_ns(measurement.timing.rayon),
                )
            })
            .collect::<Vec<_>>();
        let model = RayonCostModel::TwoWorkers(
            fit_linear_model(&points)
                .ok_or_else(|| "invalid two-worker Rayon linear fit".to_owned())?,
        );
        if measurements
            .iter()
            .filter(|measurement| measurement.chunk_plan.chunk_count() == 2)
            .all(|measurement| {
                prediction_matches(
                    model.predict(measurement.chunk_plan),
                    duration_ns(measurement.timing.rayon),
                )
            })
        {
            return Ok(model);
        }
        return Err("two-worker Rayon training prediction exceeded 25% error".to_owned());
    }

    // Normalize the columns before solving the normal equations. Fanout and
    // chunk length are several orders of magnitude larger than the dispatch
    // constant, so scaling keeps the interaction fit numerically stable.
    let scales = (0..5)
        .map(|column| {
            measurements
                .iter()
                .map(|measurement| rayon_model_features(measurement)[column].abs())
                .fold(0.0, f64::max)
                .max(1.0)
        })
        .collect::<Vec<_>>();
    let mut system = [[0.0; 6]; 5];
    for measurement in measurements {
        let mut features = rayon_model_features(measurement);
        for (feature, scale) in features.iter_mut().zip(&scales) {
            *feature /= scale;
        }
        let observed = duration_ns(measurement.timing.rayon);
        for row in 0..5 {
            for column in 0..5 {
                system[row][column] += features[row] * features[column];
            }
            system[row][5] += features[row] * observed;
        }
    }
    let [
        dispatch_ns,
        per_chunk_ns,
        per_merged_recipient_ns,
        critical_chunk_recipient_ns,
        chunk_critical_path_interaction_ns,
    ] = solve_5x5(system).ok_or_else(|| "singular Rayon interaction model".to_owned())?;
    let [
        dispatch_ns,
        per_chunk_ns,
        per_merged_recipient_ns,
        critical_chunk_recipient_ns,
        chunk_critical_path_interaction_ns,
    ] = [
        dispatch_ns / scales[0],
        per_chunk_ns / scales[1],
        per_merged_recipient_ns / scales[2],
        critical_chunk_recipient_ns / scales[3],
        chunk_critical_path_interaction_ns / scales[4],
    ];
    let coefficients = [
        dispatch_ns,
        per_chunk_ns,
        per_merged_recipient_ns,
        critical_chunk_recipient_ns,
        chunk_critical_path_interaction_ns,
    ];
    if !coefficients
        .iter()
        .all(|coefficient| coefficient.is_finite())
    {
        return Err(format!(
            "Rayon interaction model has invalid coefficients: dispatch_ns={dispatch_ns} per_chunk_ns={per_chunk_ns} per_merged_recipient_ns={per_merged_recipient_ns} critical_chunk_recipient_ns={critical_chunk_recipient_ns} chunk_critical_path_interaction_ns={chunk_critical_path_interaction_ns}"
        ));
    }

    let model = RayonCostModel::General {
        dispatch_ns,
        per_chunk_ns,
        per_merged_recipient_ns,
        critical_chunk_recipient_ns,
        chunk_critical_path_interaction_ns,
    };
    if measurements
        .iter()
        .any(|measurement| model.predict(measurement.chunk_plan) <= 0.0)
    {
        return Err("Rayon interaction model produced a non-positive prediction".to_owned());
    }
    Ok(model)
}

fn rayon_model_features(measurement: &ModelMeasurement) -> [f64; 5] {
    let chunk_count = measurement.chunk_plan.chunk_count() as f64;
    let chunk_len = measurement.chunk_plan.chunk_len() as f64;
    [
        1.0,
        chunk_count,
        measurement.fanout as f64,
        chunk_len,
        // Partition density is the chunk-count/critical-path interaction.
        chunk_count / chunk_len,
    ]
}

fn fit_linear_model(points: &[(f64, f64)]) -> Option<LinearCostModel> {
    if points.len() < 2 {
        return None;
    }

    let count = points.len() as f64;
    let sum_x = points.iter().map(|(x, _)| x).sum::<f64>();
    let sum_y = points.iter().map(|(_, y)| y).sum::<f64>();
    let sum_xx = points.iter().map(|(x, _)| x * x).sum::<f64>();
    let sum_xy = points.iter().map(|(x, y)| x * y).sum::<f64>();
    let denominator = count * sum_xx - sum_x * sum_x;
    if !denominator.is_finite() || denominator <= f64::EPSILON {
        return None;
    }

    let per_recipient_ns = (count * sum_xy - sum_x * sum_y) / denominator;
    let fixed_ns = (sum_y - per_recipient_ns * sum_x) / count;
    (fixed_ns.is_finite()
        && fixed_ns >= 0.0
        && per_recipient_ns.is_finite()
        && per_recipient_ns > 0.0)
        .then_some(LinearCostModel {
            fixed_ns,
            per_recipient_ns,
        })
}

fn solve_5x5(mut system: [[f64; 6]; 5]) -> Option<[f64; 5]> {
    for column in 0..5 {
        let pivot = (column..5).max_by(|&left, &right| {
            system[left][column]
                .abs()
                .total_cmp(&system[right][column].abs())
        })?;
        if system[pivot][column].abs() <= f64::EPSILON {
            return None;
        }
        system.swap(column, pivot);

        let divisor = system[column][column];
        for value in &mut system[column][column..] {
            *value /= divisor;
        }
        for row in 0..5 {
            if row == column {
                continue;
            }
            let factor = system[row][column];
            for entry in column..6 {
                system[row][entry] -= factor * system[column][entry];
            }
        }
    }

    let solution = std::array::from_fn(|row| system[row][5]);
    solution
        .iter()
        .all(|value| value.is_finite())
        .then_some(solution)
}

fn model_matches_holdout(
    sequential_model: LinearCostModel,
    rayon_model: RayonCostModel,
    chunk_plan: RayonChunkPlan,
    timing: CalibrationTiming,
) -> bool {
    let predicted_sequential = sequential_model.predict(chunk_plan.fanout);
    let predicted_rayon = rayon_model.predict(chunk_plan);
    prediction_matches(predicted_sequential, duration_ns(timing.sequential))
        && rayon_wins(timing)
            == rayon_wins(CalibrationTiming {
                sequential: Duration::from_nanos(predicted_sequential.max(0.0) as u64),
                rayon: Duration::from_nanos(predicted_rayon.max(0.0) as u64),
            })
}

fn select_modeled_profile(
    sequential_model: LinearCostModel,
    rayon_model: RayonCostModel,
    rayon_workers: usize,
) -> Option<ModeledProfileCandidate> {
    let tiers = modeled_dispatch_tiers(rayon_workers);
    let choices = (MIN_MODELED_FANOUT..=CALIBRATION_MAX_FANOUT)
        .map(|fanout| {
            modeled_tier_for_range(
                &tiers,
                fanout,
                fanout,
                sequential_model,
                rayon_model,
                rayon_workers,
            )
        })
        .collect::<Vec<_>>();
    let start_index = choices
        .iter()
        .rposition(Option::is_none)
        .map_or(0, |index| index + 1);
    // Require at least two fanouts in the accepted suffix. A solitary maximum
    // fanout point cannot establish a sustained crossover.
    if choices.len().saturating_sub(start_index) < 2 {
        return None;
    }

    let mut segments: Vec<ModeledScheduleSegment> = Vec::new();
    for (index, choice) in choices.iter().enumerate().skip(start_index) {
        let fanout = MIN_MODELED_FANOUT + index;
        let (tier, score) = choice.expect("the sustained suffix has a modeled Rayon winner");
        if segments.last().is_some_and(|segment| segment.tier == tier) {
            let segment = segments
                .last_mut()
                .expect("the nonempty segment list retains its last entry");
            segment.end_fanout = fanout;
            segment.score += score;
        } else {
            segments.push(ModeledScheduleSegment {
                start_fanout: fanout,
                end_fanout: fanout,
                tier,
                score,
            });
        }
    }

    coalesce_modeled_segments(
        &mut segments,
        &tiers,
        sequential_model,
        rayon_model,
        rayon_workers,
    )?;
    let breakpoints = segments
        .into_iter()
        .map(|segment| {
            RayonDispatchBreakpoint::new(
                segment.start_fanout,
                segment.tier.rayon_max_workers,
                segment.tier.rayon_min_len,
            )
        })
        .collect::<Vec<_>>();
    VoiceDispatchProfile::from_breakpoints(&breakpoints)
        .map(|profile| ModeledProfileCandidate { profile })
}

fn modeled_tier_for_range(
    tiers: &[ModeledDispatchTier],
    start_fanout: usize,
    end_fanout: usize,
    sequential_model: LinearCostModel,
    rayon_model: RayonCostModel,
    rayon_workers: usize,
) -> Option<(ModeledDispatchTier, f64)> {
    tiers
        .iter()
        .copied()
        .filter_map(|tier| {
            let mut score = 0.0;
            for fanout in start_fanout..=end_fanout {
                let chunk_plan = tier.chunk_plan(fanout, rayon_workers);
                if chunk_plan.chunk_count() < 2
                    || !model_predicts_rayon_win(
                        sequential_model.predict(fanout),
                        rayon_model.predict(chunk_plan),
                    )
                {
                    return None;
                }
                score += rayon_model.predict(chunk_plan);
            }
            Some((tier, score))
        })
        .min_by(|(left_tier, left_score), (right_tier, right_score)| {
            left_score
                .total_cmp(right_score)
                // When the predicted timing is tied, fewer workers are
                // preferable because they avoid needless task and merge
                // overhead.
                .then_with(|| {
                    left_tier
                        .rayon_max_workers
                        .cmp(&right_tier.rayon_max_workers)
                })
                .then_with(|| left_tier.rayon_min_len.cmp(&right_tier.rayon_min_len))
        })
}

fn coalesce_modeled_segments(
    segments: &mut Vec<ModeledScheduleSegment>,
    tiers: &[ModeledDispatchTier],
    sequential_model: LinearCostModel,
    rayon_model: RayonCostModel,
    rayon_workers: usize,
) -> Option<()> {
    while segments.len() > MAX_RAYON_DISPATCH_BREAKPOINTS {
        let (merge_index, merged) = (0..segments.len() - 1)
            .filter_map(|index| {
                let left = segments[index];
                let right = segments[index + 1];
                let (tier, score) = modeled_tier_for_range(
                    tiers,
                    left.start_fanout,
                    right.end_fanout,
                    sequential_model,
                    rayon_model,
                    rayon_workers,
                )?;
                Some((
                    index,
                    ModeledScheduleSegment {
                        start_fanout: left.start_fanout,
                        end_fanout: right.end_fanout,
                        tier,
                        score,
                    },
                    score - left.score - right.score,
                ))
            })
            .min_by(
                |(left_index, _, left_penalty), (right_index, _, right_penalty)| {
                    left_penalty
                        .total_cmp(right_penalty)
                        .then_with(|| left_index.cmp(right_index))
                },
            )
            .map(|(index, segment, _)| (index, segment))?;
        segments[merge_index] = merged;
        segments.remove(merge_index + 1);
    }
    Some(())
}

fn modeled_dispatch_tiers(rayon_workers: usize) -> Vec<ModeledDispatchTier> {
    let mut worker_caps = Vec::new();
    for worker_cap in [2, 3, 4, 6, 8, 12, 16, 24, 32, rayon_workers] {
        if worker_cap <= rayon_workers && !worker_caps.contains(&worker_cap) {
            worker_caps.push(worker_cap);
        }
    }

    worker_caps
        .into_iter()
        .flat_map(|rayon_max_workers| {
            CALIBRATION_TARGET_CHUNK_LENS
                .into_iter()
                .map(move |rayon_min_len| ModeledDispatchTier {
                    rayon_max_workers,
                    rayon_min_len,
                })
        })
        .collect()
}

async fn confirm_modeled_profile(
    encoded: &CalibrationEncoded,
    candidate: ModeledProfileCandidate,
    rayon_workers: usize,
) -> Result<(), String> {
    for fanout in confirmation_fanouts(candidate.profile) {
        let chunk_plan = candidate.profile.rayon_chunk_plan(fanout, rayon_workers);
        let timing = measure_median_pair(
            encoded,
            fanout,
            chunk_plan,
            CONFIRMATION_WARMUPS,
            CONFIRMATION_SAMPLES,
        )
        .await?;
        if !rayon_wins(timing) {
            return Err(format!(
                "confirmation fanout {fanout} did not meet 5% Rayon win: sequential_ns={} rayon_ns={}",
                timing.sequential.as_nanos(),
                timing.rayon.as_nanos()
            ));
        }
    }
    Ok(())
}

fn confirmation_fanouts(profile: VoiceDispatchProfile) -> Vec<usize> {
    let breakpoints = profile.breakpoints();
    let mut fanouts = Vec::with_capacity(breakpoints.len() * 2);
    for (index, breakpoint) in breakpoints.iter().enumerate() {
        let start_fanout = breakpoint.fanout_threshold();
        let end_fanout = breakpoints
            .get(index + 1)
            .map_or(CALIBRATION_MAX_FANOUT, |next| next.fanout_threshold() - 1);
        fanouts.push(start_fanout);
        if end_fanout != start_fanout {
            // The endpoint also exercises any chunk-count transitions caused
            // by the tier's target batch size before the next tier begins.
            fanouts.push(end_fanout);
        }
    }
    fanouts
}

fn duration_ns(duration: Duration) -> f64 {
    duration.as_nanos() as f64
}

fn prediction_matches(predicted: f64, observed: f64) -> bool {
    predicted.is_finite()
        && observed.is_finite()
        && observed > 0.0
        && (predicted - observed).abs() / observed <= MODEL_MAX_RELATIVE_ERROR
}

fn model_predicts_rayon_win(sequential_ns: f64, rayon_ns: f64) -> bool {
    sequential_ns.is_finite()
        && rayon_ns.is_finite()
        && sequential_ns > 0.0
        && rayon_ns > 0.0
        && rayon_ns * 100.0 <= sequential_ns * RAYON_WIN_PERCENT as f64
}

fn rayon_wins(timing: CalibrationTiming) -> bool {
    timing.rayon.as_nanos() * 100 <= timing.sequential.as_nanos() * RAYON_WIN_PERCENT
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model_measurement(
        fanout: usize,
        requested_chunks: usize,
        rayon_workers: usize,
        sequential_ns: u64,
        rayon_ns: u64,
    ) -> ModelMeasurement {
        ModelMeasurement {
            fanout,
            chunk_plan: RayonChunkPlan::with_chunk_count(fanout, requested_chunks, rayon_workers),
            timing: CalibrationTiming {
                sequential: Duration::from_nanos(sequential_ns),
                rayon: Duration::from_nanos(rayon_ns),
            },
        }
    }

    #[test]
    fn fits_known_cost_models_and_validates_a_holdout() {
        let sequential = LinearCostModel {
            fixed_ns: 1_000.0,
            per_recipient_ns: 100.0,
        };
        let rayon = RayonCostModel::General {
            dispatch_ns: 2_000.0,
            per_chunk_ns: 300.0,
            per_merged_recipient_ns: 5.0,
            critical_chunk_recipient_ns: 60.0,
            chunk_critical_path_interaction_ns: 40.0,
        };
        let measurements = model_training_probes(4)
            .into_iter()
            .map(|probe| {
                let plan = probe.chunk_plan(4);
                model_measurement(
                    probe.fanout,
                    probe.requested_chunks,
                    4,
                    sequential.predict(probe.fanout) as u64,
                    rayon.predict(plan) as u64,
                )
            })
            .collect::<Vec<_>>();

        let fitted_sequential = fit_sequential_model(&measurements).expect("sequential model fits");
        let fitted_rayon = fit_rayon_model(&measurements, 4).expect("Rayon model fits");
        let holdout_probe = model_holdout_probe(4);
        let holdout_plan = holdout_probe.chunk_plan(4);
        let holdout = CalibrationTiming {
            sequential: Duration::from_nanos(sequential.predict(holdout_probe.fanout) as u64),
            rayon: Duration::from_nanos(rayon.predict(holdout_plan) as u64),
        };

        assert!(model_matches_holdout(
            fitted_sequential,
            fitted_rayon,
            holdout_plan,
            holdout
        ));
    }

    #[test]
    fn fits_the_two_worker_model_and_selects_two_way_parallelism() {
        let sequential = LinearCostModel {
            fixed_ns: 1_000.0,
            per_recipient_ns: 100.0,
        };
        let rayon = LinearCostModel {
            fixed_ns: 2_000.0,
            per_recipient_ns: 30.0,
        };
        let measurements = model_training_probes(2)
            .into_iter()
            .map(|probe| {
                model_measurement(
                    probe.fanout,
                    probe.requested_chunks,
                    2,
                    sequential.predict(probe.fanout) as u64,
                    rayon.predict(probe.fanout) as u64,
                )
            })
            .collect::<Vec<_>>();

        let fitted_sequential = fit_sequential_model(&measurements).expect("sequential model fits");
        let fitted_rayon = fit_rayon_model(&measurements, 2).expect("Rayon model fits");
        let candidate = select_modeled_profile(fitted_sequential, fitted_rayon, 2)
            .expect("model predicts a two-worker crossover");
        let plan = candidate
            .profile
            .rayon_chunk_plan(candidate.profile.fanout_threshold(), 2);

        assert_eq!(plan.chunk_count(), 2);
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
    fn rejects_singular_and_negative_cost_models() {
        assert!(fit_linear_model(&[(64.0, 100.0), (64.0, 200.0)]).is_none());
        assert!(fit_linear_model(&[(64.0, 200.0), (128.0, 100.0)]).is_none());
    }

    #[test]
    fn tolerates_timer_noise_that_pushes_the_linear_intercept_below_zero() {
        let measurements = [
            model_measurement(64, 2, 8, 390_000, 2_000_000),
            model_measurement(64, 2, 8, 400_000, 2_000_000),
            model_measurement(512, 2, 8, 3_200_000, 2_000_000),
            model_measurement(512, 2, 8, 3_210_000, 2_000_000),
        ];
        let model =
            fit_sequential_model(&measurements).expect("positive sequential slope remains usable");
        assert_eq!(model.fixed_ns, 0.0);
        assert!(model.per_recipient_ns > 0.0);
    }

    #[test]
    fn sequential_fit_uses_one_robust_point_per_fanout() {
        let measurements = [
            (64, 1_000_000, 2_000_000),
            (64, 1_100_000, 2_000_000),
            (512, 5_600_000, 2_000_000),
            (512, 5_700_000, 2_000_000),
            (2_048, 21_000_000, 2_000_000),
            (2_048, 21_100_000, 2_000_000),
        ]
        .into_iter()
        .map(|(fanout, sequential_ns, rayon_ns)| {
            model_measurement(fanout, 2, 8, sequential_ns, rayon_ns)
        })
        .collect::<Vec<_>>();

        let model = fit_sequential_model(&measurements).expect("sequential model fits");
        assert!(prediction_matches(model.predict(1_024), 10_650_000.0));
    }

    #[test]
    fn interaction_model_accepts_chunk_scaling_without_negative_coefficients() {
        let sequential = LinearCostModel {
            fixed_ns: 1_000.0,
            per_recipient_ns: 100.0,
        };
        let rayon = RayonCostModel::General {
            dispatch_ns: 2_000.0,
            per_chunk_ns: 300.0,
            per_merged_recipient_ns: 5.0,
            critical_chunk_recipient_ns: 60.0,
            chunk_critical_path_interaction_ns: 20_000.0,
        };
        let measurements = model_training_probes(8)
            .into_iter()
            .map(|probe| {
                let plan = probe.chunk_plan(8);
                model_measurement(
                    probe.fanout,
                    probe.requested_chunks,
                    8,
                    sequential.predict(probe.fanout) as u64,
                    rayon.predict(plan) as u64,
                )
            })
            .collect::<Vec<_>>();

        let fitted = fit_rayon_model(&measurements, 8).expect("interaction model fits");
        assert!(matches!(fitted, RayonCostModel::General { .. }));
    }

    #[test]
    fn selects_only_sustained_modeled_rayon_wins() {
        let sequential = LinearCostModel {
            fixed_ns: 10_000.0,
            per_recipient_ns: 100.0,
        };
        let rayon = RayonCostModel::General {
            dispatch_ns: 20_000.0,
            per_chunk_ns: 500.0,
            per_merged_recipient_ns: 5.0,
            critical_chunk_recipient_ns: 30.0,
            chunk_critical_path_interaction_ns: 40.0,
        };
        let candidate = select_modeled_profile(sequential, rayon, 8)
            .expect("model predicts a sustained Rayon crossover");
        let threshold_plan = candidate
            .profile
            .rayon_chunk_plan(candidate.profile.fanout_threshold(), 8);

        assert!(threshold_plan.chunk_count() >= 2);
        assert!(candidate.profile.breakpoints().len() > 1);
        assert!(
            candidate
                .profile
                .breakpoints()
                .windows(2)
                .all(|pair| pair[0].fanout_threshold() < pair[1].fanout_threshold())
        );
        for breakpoint in candidate.profile.breakpoints() {
            let plan = candidate
                .profile
                .rayon_chunk_plan(breakpoint.fanout_threshold(), 8);
            assert!(plan.chunk_count() >= 2);
        }
        assert!(
            select_modeled_profile(
                sequential,
                RayonCostModel::General {
                    dispatch_ns: 1_000_000_000.0,
                    per_chunk_ns: 500.0,
                    per_merged_recipient_ns: 5.0,
                    critical_chunk_recipient_ns: 30.0,
                    chunk_critical_path_interaction_ns: 40.0,
                },
                8,
            )
            .is_none()
        );
    }

    #[test]
    fn coalesces_rounding_oscillations_without_delaying_the_crossover() {
        let sequential = LinearCostModel {
            fixed_ns: 10_000.0,
            per_recipient_ns: 100.0,
        };
        let rayon = RayonCostModel::General {
            dispatch_ns: 20_000.0,
            per_chunk_ns: 500.0,
            per_merged_recipient_ns: 5.0,
            critical_chunk_recipient_ns: 30.0,
            chunk_critical_path_interaction_ns: 40.0,
        };
        let candidate = select_modeled_profile(sequential, rayon, 32)
            .expect("the modeled crossover is sustained");

        assert_eq!(candidate.profile.fanout_threshold(), MIN_MODELED_FANOUT);
        assert!(
            candidate.profile.breakpoints().len() <= MAX_RAYON_DISPATCH_BREAKPOINTS,
            "the bounded schedule coalesces ceiling-division oscillations"
        );
        for fanout in candidate.profile.fanout_threshold()..=CALIBRATION_MAX_FANOUT {
            let chunk_plan = candidate.profile.rayon_chunk_plan(fanout, 32);
            assert!(model_predicts_rayon_win(
                sequential.predict(fanout),
                rayon.predict(chunk_plan),
            ));
        }
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
    fn confirmation_covers_each_breakpoint_and_its_tier_endpoint() {
        let profile = VoiceDispatchProfile::from_breakpoints(&[
            RayonDispatchBreakpoint::new(512, 2, 256),
            RayonDispatchBreakpoint::new(1_024, 4, 512),
            RayonDispatchBreakpoint::new(1_536, 4, 512),
        ])
        .expect("valid calibrated breakpoint schedule");

        assert_eq!(
            confirmation_fanouts(profile),
            vec![512, 1_023, 1_024, 1_535, 1_536, CALIBRATION_MAX_FANOUT]
        );
    }

    #[test]
    fn wide_pool_training_includes_the_full_worker_shape_before_holdout() {
        let training = model_training_probes(8);
        assert!(training.contains(&ModelProbe {
            fanout: 512,
            requested_chunks: 8,
        }));
        assert!(training.contains(&ModelProbe {
            fanout: CALIBRATION_MAX_FANOUT,
            requested_chunks: 8,
        }));
        assert_eq!(
            model_holdout_probe(8),
            ModelProbe {
                fanout: 1_024,
                requested_chunks: 8,
            }
        );
        assert!(!training.contains(&model_holdout_probe(8)));

        let two_worker_training = model_training_probes(2);
        assert!(two_worker_training.contains(&ModelProbe {
            fanout: CALIBRATION_MAX_FANOUT,
            requested_chunks: 2,
        }));
        assert!(!two_worker_training.contains(&model_holdout_probe(2)));
    }

    #[test]
    fn requires_a_five_percent_measured_confirmation_win() {
        assert!(rayon_wins(CalibrationTiming {
            sequential: Duration::from_micros(100),
            rayon: Duration::from_micros(95),
        }));
        assert!(!rayon_wins(CalibrationTiming {
            sequential: Duration::from_micros(100),
            rayon: Duration::from_micros(96),
        }));
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
