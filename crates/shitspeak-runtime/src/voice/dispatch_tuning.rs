use std::{
    collections::HashMap,
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
const CONSERVATIVE_RAYON_MIN_LEN: usize = 256;
const CALIBRATION_KEY: [u8; 16] = [0x42; 16];
const CALIBRATION_IV_E: [u8; 16] = [0x01; 16];
const CALIBRATION_IV_D: [u8; 16] = [0x02; 16];
const CALIBRATION_MAX_FANOUT: usize = 2048;
const CALIBRATION_TARGET_CHUNK_LENS: [usize; 9] = [8, 16, 24, 32, 48, 64, 128, 256, 512];
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct VoiceDispatchProfile {
    fanout_threshold: usize,
    rayon_min_len: usize,
}

impl VoiceDispatchProfile {
    const fn new(fanout_threshold: usize, rayon_min_len: usize) -> Self {
        Self {
            fanout_threshold,
            rayon_min_len,
        }
    }

    const fn sequential_only() -> Self {
        Self::new(usize::MAX, CONSERVATIVE_RAYON_MIN_LEN)
    }

    pub(crate) fn uses_rayon(self, fanout: usize) -> bool {
        fanout >= self.fanout_threshold
    }

    pub(crate) fn fanout_threshold(self) -> usize {
        self.fanout_threshold
    }

    pub(crate) fn rayon_min_len(self) -> usize {
        self.rayon_min_len
    }

    pub(crate) fn rayon_chunk_plan(self, fanout: usize, rayon_workers: usize) -> RayonChunkPlan {
        RayonChunkPlan::new(fanout, self.rayon_min_len, rayon_workers)
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

#[derive(Clone, Copy, PartialEq, Eq)]
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
            } => {
                dispatch_ns
                    + per_chunk_ns * chunk_plan.chunk_count() as f64
                    + per_merged_recipient_ns * chunk_plan.fanout as f64
                    + critical_chunk_recipient_ns * chunk_plan.chunk_len() as f64
            }
        }
    }
}

#[derive(Clone, Copy)]
struct ModeledProfileCandidate {
    profile: VoiceDispatchProfile,
    confirmation_fanouts: [usize; 2],
    score: f64,
}

async fn calibrate_voice_dispatch_plan(rayon_workers: usize) -> Result<VoiceDispatchPlan, String> {
    let small_payload = make_calibration_encoded(170)?;
    let large_payload = make_calibration_encoded(768)?;
    let small_profile = calibrate_payload_profile(&small_payload, rayon_workers).await?;
    let large_profile = calibrate_payload_profile(&large_payload, rayon_workers).await?;

    Ok(VoiceDispatchPlan::calibrated(small_profile, large_profile))
}

async fn calibrate_payload_profile(
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

    let Some(sequential_model) = fit_sequential_model(&measurements) else {
        tracing::info!("voice dispatch model fit was not usable; selecting sequential dispatch");
        return Ok(VoiceDispatchProfile::sequential_only());
    };
    let Some(rayon_model) = fit_rayon_model(&measurements, rayon_workers) else {
        tracing::info!("voice dispatch model fit was not usable; selecting sequential dispatch");
        return Ok(VoiceDispatchProfile::sequential_only());
    };

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
            "voice dispatch model did not match its holdout probe; selecting sequential dispatch"
        );
        return Ok(VoiceDispatchProfile::sequential_only());
    }

    let Some(candidate) = select_modeled_profile(sequential_model, rayon_model, rayon_workers)
    else {
        return Ok(VoiceDispatchProfile::sequential_only());
    };

    if confirm_modeled_profile(encoded, candidate, rayon_workers).await? {
        Ok(candidate.profile)
    } else {
        tracing::info!(
            "voice dispatch model crossover confirmation failed; selecting sequential dispatch"
        );
        Ok(VoiceDispatchProfile::sequential_only())
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
        ];
    }

    let coarse_chunks = rayon_workers.min(4);
    vec![
        ModelProbe {
            fanout: 64,
            requested_chunks: 1,
        },
        ModelProbe {
            fanout: 64,
            requested_chunks: 2,
        },
        ModelProbe {
            fanout: 512,
            requested_chunks: 2,
        },
        ModelProbe {
            fanout: 512,
            requested_chunks: coarse_chunks,
        },
        ModelProbe {
            fanout: CALIBRATION_MAX_FANOUT,
            requested_chunks: 2,
        },
        ModelProbe {
            fanout: CALIBRATION_MAX_FANOUT,
            requested_chunks: coarse_chunks,
        },
    ]
}

fn model_holdout_probe(rayon_workers: usize) -> ModelProbe {
    if rayon_workers == 2 || rayon_workers > 4 {
        ModelProbe {
            fanout: CALIBRATION_MAX_FANOUT,
            requested_chunks: rayon_workers,
        }
    } else {
        ModelProbe {
            fanout: 1024,
            requested_chunks: rayon_workers,
        }
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

fn fit_sequential_model(measurements: &[ModelMeasurement]) -> Option<LinearCostModel> {
    let points = measurements
        .iter()
        .map(|measurement| {
            (
                measurement.fanout as f64,
                duration_ns(measurement.timing.sequential),
            )
        })
        .collect::<Vec<_>>();
    let model = fit_linear_model(&points)?;
    measurements
        .iter()
        .all(|measurement| {
            prediction_matches(
                model.predict(measurement.fanout),
                duration_ns(measurement.timing.sequential),
            )
        })
        .then_some(model)
}

fn fit_rayon_model(
    measurements: &[ModelMeasurement],
    rayon_workers: usize,
) -> Option<RayonCostModel> {
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
        let model = RayonCostModel::TwoWorkers(fit_linear_model(&points)?);
        return measurements
            .iter()
            .filter(|measurement| measurement.chunk_plan.chunk_count() == 2)
            .all(|measurement| {
                prediction_matches(
                    model.predict(measurement.chunk_plan),
                    duration_ns(measurement.timing.rayon),
                )
            })
            .then_some(model);
    }

    let mut system = [[0.0; 5]; 4];
    for measurement in measurements {
        let features = [
            1.0,
            measurement.chunk_plan.chunk_count() as f64,
            measurement.fanout as f64,
            measurement.chunk_plan.chunk_len() as f64,
        ];
        let observed = duration_ns(measurement.timing.rayon);
        for row in 0..4 {
            for column in 0..4 {
                system[row][column] += features[row] * features[column];
            }
            system[row][4] += features[row] * observed;
        }
    }
    let [
        dispatch_ns,
        per_chunk_ns,
        per_merged_recipient_ns,
        critical_chunk_recipient_ns,
    ] = solve_4x4(system)?;
    let coefficients = [
        dispatch_ns,
        per_chunk_ns,
        per_merged_recipient_ns,
        critical_chunk_recipient_ns,
    ];
    if !coefficients
        .iter()
        .all(|coefficient| coefficient.is_finite() && *coefficient >= 0.0)
        || critical_chunk_recipient_ns == 0.0
    {
        return None;
    }

    let model = RayonCostModel::General {
        dispatch_ns,
        per_chunk_ns,
        per_merged_recipient_ns,
        critical_chunk_recipient_ns,
    };
    measurements
        .iter()
        .all(|measurement| {
            prediction_matches(
                model.predict(measurement.chunk_plan),
                duration_ns(measurement.timing.rayon),
            )
        })
        .then_some(model)
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

fn solve_4x4(mut system: [[f64; 5]; 4]) -> Option<[f64; 4]> {
    for column in 0..4 {
        let pivot = (column..4).max_by(|&left, &right| {
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
        for row in 0..4 {
            if row == column {
                continue;
            }
            let factor = system[row][column];
            for entry in column..5 {
                system[row][entry] -= factor * system[column][entry];
            }
        }
    }

    let solution = std::array::from_fn(|row| system[row][4]);
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
    prediction_matches(
        sequential_model.predict(chunk_plan.fanout),
        duration_ns(timing.sequential),
    ) && prediction_matches(rayon_model.predict(chunk_plan), duration_ns(timing.rayon))
}

fn select_modeled_profile(
    sequential_model: LinearCostModel,
    rayon_model: RayonCostModel,
    rayon_workers: usize,
) -> Option<ModeledProfileCandidate> {
    let mut best = None;

    for target_chunk_len in CALIBRATION_TARGET_CHUNK_LENS {
        let points = (2..=CALIBRATION_MAX_FANOUT)
            .filter_map(|fanout| {
                let chunk_plan = RayonChunkPlan::new(fanout, target_chunk_len, rayon_workers);
                (chunk_plan.chunk_count() >= 2).then(|| {
                    (
                        fanout,
                        sequential_model.predict(fanout),
                        rayon_model.predict(chunk_plan),
                    )
                })
            })
            .collect::<Vec<_>>();

        for start in 0..points.len().saturating_sub(1) {
            let suffix = &points[start..];
            if !suffix.iter().all(|(_, sequential_ns, rayon_ns)| {
                model_predicts_rayon_win(*sequential_ns, *rayon_ns)
            }) {
                continue;
            }

            let candidate = ModeledProfileCandidate {
                profile: VoiceDispatchProfile::new(points[start].0, target_chunk_len),
                confirmation_fanouts: confirmation_fanouts(
                    points[start].0,
                    target_chunk_len,
                    rayon_workers,
                ),
                score: suffix.iter().map(|(_, _, rayon_ns)| rayon_ns).sum(),
            };
            if best.is_none_or(|current| modeled_candidate_is_better(candidate, current)) {
                best = Some(candidate);
            }
        }
    }

    best
}

fn confirmation_fanouts(
    threshold: usize,
    target_chunk_len: usize,
    rayon_workers: usize,
) -> [usize; 2] {
    let threshold_plan = RayonChunkPlan::new(threshold, target_chunk_len, rayon_workers);
    let later_fanout = ((threshold + 1)..=CALIBRATION_MAX_FANOUT)
        .find(|&fanout| {
            RayonChunkPlan::new(fanout, target_chunk_len, rayon_workers).chunk_count()
                > threshold_plan.chunk_count()
        })
        // Once the plan is capped at the worker count, confirm at the largest
        // modeled workload so the second probe still exercises a distinctly
        // larger recipient run.
        .unwrap_or(CALIBRATION_MAX_FANOUT);
    [threshold, later_fanout]
}

fn modeled_candidate_is_better(
    candidate: ModeledProfileCandidate,
    current: ModeledProfileCandidate,
) -> bool {
    candidate.profile.fanout_threshold() < current.profile.fanout_threshold()
        || (candidate.profile.fanout_threshold() == current.profile.fanout_threshold()
            && (candidate.score < current.score
                || (candidate.score == current.score
                    && candidate.profile.rayon_min_len() < current.profile.rayon_min_len())))
}

async fn confirm_modeled_profile(
    encoded: &CalibrationEncoded,
    candidate: ModeledProfileCandidate,
    rayon_workers: usize,
) -> Result<bool, String> {
    for fanout in candidate.confirmation_fanouts {
        let chunk_plan =
            RayonChunkPlan::new(fanout, candidate.profile.rayon_min_len(), rayon_workers);
        let timing = measure_median_pair(
            encoded,
            fanout,
            chunk_plan,
            CONFIRMATION_WARMUPS,
            CONFIRMATION_SAMPLES,
        )
        .await?;
        if !rayon_wins(timing) {
            return Ok(false);
        }
    }
    Ok(true)
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
        let plan = RayonChunkPlan::new(
            candidate.profile.fanout_threshold(),
            candidate.profile.rayon_min_len(),
            2,
        );

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
        };
        let candidate = select_modeled_profile(sequential, rayon, 8)
            .expect("model predicts a sustained Rayon crossover");
        let threshold_plan = RayonChunkPlan::new(
            candidate.profile.fanout_threshold(),
            candidate.profile.rayon_min_len(),
            8,
        );

        assert!(threshold_plan.chunk_count() >= 2);
        assert_eq!(
            candidate.confirmation_fanouts[0],
            candidate.profile.fanout_threshold()
        );
        let confirmation_plan = RayonChunkPlan::new(
            candidate.confirmation_fanouts[1],
            candidate.profile.rayon_min_len(),
            8,
        );
        assert!(confirmation_plan.chunk_count() > threshold_plan.chunk_count());
        assert!(
            select_modeled_profile(
                sequential,
                RayonCostModel::General {
                    dispatch_ns: 1_000_000_000.0,
                    per_chunk_ns: 500.0,
                    per_merged_recipient_ns: 5.0,
                    critical_chunk_recipient_ns: 30.0,
                },
                8,
            )
            .is_none()
        );
    }

    #[test]
    fn confirmation_exercises_the_next_chunk_count_transition() {
        assert_eq!(confirmation_fanouts(9, 8, 8), [9, 17]);
        assert_eq!(confirmation_fanouts(9, 8, 2), [9, CALIBRATION_MAX_FANOUT]);
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
