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
const CALIBRATION_FANOUTS: [usize; 6] = [64, 128, 256, 512, 1024, 2048];
const CALIBRATION_MIN_LENS: [usize; 4] = [64, 128, 256, 512];
const CALIBRATION_WARMUPS: usize = 2;
const CALIBRATION_SAMPLES: usize = 11;
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
        VoiceDispatchMode::StartupCalibrated => match calibrate_voice_dispatch_plan().await {
            Ok(plan) => plan,
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    "voice dispatch calibration failed; using conservative fallback"
                );
                VoiceDispatchPlan::conservative()
            }
        },
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
struct CalibrationMeasurement {
    fanout: usize,
    min_len: usize,
    sequential: Duration,
    rayon: Duration,
}

async fn calibrate_voice_dispatch_plan() -> Result<VoiceDispatchPlan, String> {
    let small_payload = make_calibration_encoded(170)?;
    let large_payload = make_calibration_encoded(768)?;
    let small_profile = calibrate_payload_profile(&small_payload).await?;
    let large_profile = calibrate_payload_profile(&large_payload).await?;

    Ok(VoiceDispatchPlan::calibrated(small_profile, large_profile))
}

async fn calibrate_payload_profile(
    encoded: &CalibrationEncoded,
) -> Result<VoiceDispatchProfile, String> {
    let mut measurements = Vec::new();

    for min_len in CALIBRATION_MIN_LENS {
        for fanout in CALIBRATION_FANOUTS {
            if min_len > fanout {
                continue;
            }

            for warmup in 0..CALIBRATION_WARMUPS {
                let _ = measure_pair(encoded, fanout, min_len, warmup % 2 == 0).await?;
            }

            let mut sequential = Vec::with_capacity(CALIBRATION_SAMPLES);
            let mut rayon = Vec::with_capacity(CALIBRATION_SAMPLES);
            for sample in 0..CALIBRATION_SAMPLES {
                let (sequential_sample, rayon_sample) =
                    measure_pair(encoded, fanout, min_len, sample % 2 == 0).await?;
                sequential.push(sequential_sample);
                rayon.push(rayon_sample);
            }

            measurements.push(CalibrationMeasurement {
                fanout,
                min_len,
                sequential: median_duration(&mut sequential),
                rayon: median_duration(&mut rayon),
            });
        }
    }

    Ok(select_profile(&measurements))
}

async fn measure_pair(
    encoded: &CalibrationEncoded,
    fanout: usize,
    min_len: usize,
    rayon_first: bool,
) -> Result<(Duration, Duration), String> {
    let sequential_work = make_workload(fanout)?;
    let rayon_work = make_workload(fanout)?;

    if rayon_first {
        let rayon = time_rayon(rayon_work, encoded.clone(), min_len).await?;
        let sequential = time_sequential(sequential_work, encoded);
        Ok((sequential, rayon))
    } else {
        let sequential = time_sequential(sequential_work, encoded);
        let rayon = time_rayon(rayon_work, encoded.clone(), min_len).await?;
        Ok((sequential, rayon))
    }
}

fn time_sequential(workload: CalibrationWorkload, encoded: &CalibrationEncoded) -> Duration {
    let started_at = Instant::now();
    let mut batches = HashMap::<SocketAddr, DatagramBatch>::new();
    for recipient in workload.recipients {
        encrypt_recipient(&mut batches, recipient, encoded);
    }
    black_box(batches);
    started_at.elapsed()
}

async fn time_rayon(
    workload: CalibrationWorkload,
    encoded: CalibrationEncoded,
    min_len: usize,
) -> Result<Duration, String> {
    let started_at = Instant::now();
    tokio::task::spawn_blocking(move || {
        let batches = workload
            .recipients
            .into_par_iter()
            .with_min_len(min_len)
            .fold(
                HashMap::<SocketAddr, DatagramBatch>::new,
                |mut batches, recipient| {
                    encrypt_recipient(&mut batches, recipient, &encoded);
                    batches
                },
            )
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
    recipient: CalibrationRecipient,
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

fn select_profile(measurements: &[CalibrationMeasurement]) -> VoiceDispatchProfile {
    let mut best: Option<(usize, u128, usize, usize)> = None;

    for min_len in CALIBRATION_MIN_LENS {
        let candidates = measurements
            .iter()
            .filter(|measurement| measurement.min_len == min_len)
            .collect::<Vec<_>>();
        for start in 0..candidates.len() {
            let suffix = &candidates[start..];
            if suffix.len() < 2 || !suffix.iter().all(|measurement| rayon_wins(**measurement)) {
                continue;
            }

            let score = suffix
                .iter()
                .map(|measurement| measurement.rayon.as_nanos())
                .sum::<u128>();
            let candidate = (candidates[start].fanout, score, min_len, start);
            if best.is_none_or(|current| candidate < current) {
                best = Some(candidate);
            }
        }
    }

    match best {
        Some((threshold, _, min_len, _)) => VoiceDispatchProfile::new(threshold, min_len),
        None => VoiceDispatchProfile::sequential_only(),
    }
}

fn rayon_wins(measurement: CalibrationMeasurement) -> bool {
    measurement.rayon.as_nanos() * 100 <= measurement.sequential.as_nanos() * RAYON_WIN_PERCENT
}

#[cfg(test)]
mod tests {
    use super::*;

    fn measurement(
        fanout: usize,
        min_len: usize,
        sequential_us: u64,
        rayon_us: u64,
    ) -> CalibrationMeasurement {
        CalibrationMeasurement {
            fanout,
            min_len,
            sequential: Duration::from_micros(sequential_us),
            rayon: Duration::from_micros(rayon_us),
        }
    }

    #[test]
    fn selects_lowest_sustained_winning_threshold() {
        let measurements = vec![
            measurement(64, 64, 100, 110),
            measurement(128, 64, 100, 90),
            measurement(256, 64, 100, 92),
            measurement(64, 128, 100, 100),
            measurement(128, 128, 100, 94),
            measurement(256, 128, 100, 93),
        ];

        assert_eq!(
            select_profile(&measurements),
            VoiceDispatchProfile::new(128, 64)
        );
    }

    #[test]
    fn rejects_an_isolated_rayon_win() {
        let measurements = vec![
            measurement(64, 64, 100, 90),
            measurement(128, 64, 100, 110),
            measurement(256, 64, 100, 90),
        ];

        assert_eq!(
            select_profile(&measurements),
            VoiceDispatchProfile::sequential_only()
        );
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
