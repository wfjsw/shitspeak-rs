//! Pure marginal-utility scoring for proactive voice repair candidates.
//!
//! Copy demand remains a separate policy. This module only compares repair
//! opportunities that policy has already generated. All arithmetic is fixed
//! point so one immutable quality batch produces deterministic scores.
//!
//! Diversity is deliberately a limited proxy: a distinct first hop is
//! required, and using a different physical transport kind receives more
//! credit than reusing the same kind. It does not claim to know downstream
//! edge overlap, shared transit, or whether QUIC uses DATAGRAM versus a stream.

use std::time::Duration;

use crate::overlay::VoiceRouteQuality;

const MICROS_SCALE: u64 = 1_000_000;
const TERMINATOR_VALUE_MICROS: u64 = 1_250_000;
const SAME_TRANSPORT_DIVERSITY_MICROS: u64 = 750_000;
const DIFFERENT_TRANSPORT_DIVERSITY_MICROS: u64 = MICROS_SCALE;
const MAX_URGENCY_BONUS_MICROS: u64 = 500_000;
const SECOND_COPY_INDEPENDENCE_MICROS: u64 = 250_000;

/// Return the marginal utility of one already-requested proactive copy.
///
/// `original_need_micros` is the caller's independently computed probability
/// or normalized pressure that the original needs repair. It is clamped to
/// one fixed-point unit. `copy_index` is zero for the first copy and one for
/// the second; later copies are intentionally assigned no utility.
///
/// A score of zero means the candidate is not useful with the captured
/// information: its alternate is missing or unmeasured, its first hop is not
/// diverse, or it cannot arrive before the remaining deadline.
pub(crate) fn proactive_marginal_utility_micros(
    original_need_micros: u64,
    remaining: Duration,
    is_terminator: bool,
    copy_index: usize,
    quality: VoiceRouteQuality,
) -> u64 {
    let original_need = original_need_micros.min(MICROS_SCALE);
    if original_need == 0 || copy_index > 1 {
        return 0;
    }

    let Some(alternate_next_hop) = quality.alternate_next_hop() else {
        return 0;
    };
    if alternate_next_hop == quality.next_hop() {
        return 0;
    }
    let (
        Some(alternate_latency_us),
        Some(alternate_transport),
        Some(alternate_loss_ppm),
        Some(alternate_jitter_us),
    ) = (
        quality.alternate_path_latency_us(),
        quality.alternate_transport(),
        quality.alternate_loss_ppm(),
        quality.alternate_jitter_us(),
    )
    else {
        return 0;
    };

    let remaining_us = u64::try_from(remaining.as_micros()).unwrap_or(u64::MAX);
    let on_time_probability =
        on_time_probability_micros(remaining_us, alternate_latency_us, alternate_jitter_us);
    if on_time_probability == 0 {
        return 0;
    }
    let wire_probability = MICROS_SCALE.saturating_sub(u64::from(alternate_loss_ppm));
    let repair_probability = mul_micros(on_time_probability, wire_probability);
    if repair_probability == 0 {
        return 0;
    }

    let frame_value = if is_terminator {
        TERMINATOR_VALUE_MICROS
    } else {
        MICROS_SCALE
    };
    let diversity = if alternate_transport == quality.transport() {
        SAME_TRANSPORT_DIVERSITY_MICROS
    } else {
        DIFFERENT_TRANSPORT_DIVERSITY_MICROS
    };
    let urgency = deadline_urgency_micros(remaining_us, alternate_latency_us, alternate_jitter_us);
    let diminishing_return = match copy_index {
        0 => MICROS_SCALE,
        1 => mul_micros(
            MICROS_SCALE.saturating_sub(repair_probability),
            SECOND_COPY_INDEPENDENCE_MICROS,
        ),
        _ => 0,
    };
    if diminishing_return == 0 {
        return 0;
    }

    [
        repair_probability,
        frame_value,
        diversity,
        urgency,
        diminishing_return,
    ]
    .into_iter()
    .fold(original_need, mul_micros)
}

fn on_time_probability_micros(remaining_us: u64, path_latency_us: u64, jitter_us: u64) -> u64 {
    if remaining_us <= path_latency_us {
        return 0;
    }
    if jitter_us == 0 {
        return MICROS_SCALE;
    }
    let slack_us = remaining_us - path_latency_us;
    let jitter_window_us = jitter_us.saturating_mul(3).max(1);
    ratio_micros(slack_us, jitter_window_us).min(MICROS_SCALE)
}

fn deadline_urgency_micros(remaining_us: u64, path_latency_us: u64, jitter_us: u64) -> u64 {
    let predicted_arrival_us = path_latency_us.saturating_add(jitter_us.saturating_mul(3));
    let bonus = ratio_micros(predicted_arrival_us, remaining_us.max(1))
        .min(MICROS_SCALE)
        .saturating_mul(MAX_URGENCY_BONUS_MICROS)
        / MICROS_SCALE;
    MICROS_SCALE.saturating_add(bonus)
}

fn ratio_micros(numerator: u64, denominator: u64) -> u64 {
    let scaled = u128::from(numerator).saturating_mul(u128::from(MICROS_SCALE));
    (scaled / u128::from(denominator.max(1))).min(u128::from(u64::MAX)) as u64
}

fn mul_micros(left: u64, right: u64) -> u64 {
    (u128::from(left)
        .saturating_mul(u128::from(right))
        .saturating_div(u128::from(MICROS_SCALE)))
    .min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use shitspeak_s2s_transport::TransportKind;

    fn quality(
        alternate_transport: TransportKind,
        latency_us: u64,
        loss_ppm: u32,
        jitter_us: u64,
    ) -> VoiceRouteQuality {
        VoiceRouteQuality::new(2, TransportKind::Udp, 80_000, 20_000, 8_000)
            .with_alternate_route_quality(3, latency_us, alternate_transport, loss_ppm, jitter_us)
    }

    fn utility(
        remaining_ms: u64,
        is_terminator: bool,
        copy_index: usize,
        quality: VoiceRouteQuality,
    ) -> u64 {
        proactive_marginal_utility_micros(
            MICROS_SCALE,
            Duration::from_millis(remaining_ms),
            is_terminator,
            copy_index,
            quality,
        )
    }

    #[test]
    fn marginal_utility_components_are_monotonic_and_bounded() {
        let baseline = quality(TransportKind::Quic, 100_000, 10_000, 10_000);
        let baseline_utility = utility(500, false, 0, baseline);
        assert!(baseline_utility > 0);
        assert!(baseline_utility <= 1_875_000);

        let cases = [
            (
                "slower and more jittery alternate",
                utility(
                    500,
                    false,
                    0,
                    quality(TransportKind::Quic, 450_000, 10_000, 50_000),
                ),
                baseline_utility,
            ),
            (
                "lossier alternate",
                utility(
                    500,
                    false,
                    0,
                    quality(TransportKind::Quic, 100_000, 200_000, 10_000),
                ),
                baseline_utility,
            ),
            (
                "same transport failure domain",
                utility(
                    500,
                    false,
                    0,
                    quality(TransportKind::Udp, 100_000, 10_000, 10_000),
                ),
                baseline_utility,
            ),
            (
                "ordinary frame value",
                baseline_utility,
                utility(500, true, 0, baseline),
            ),
            (
                "second-copy marginal value",
                utility(500, false, 1, baseline),
                baseline_utility,
            ),
        ];
        for (name, lower, higher) in cases {
            assert!(lower < higher, "{name}: {lower} must be below {higher}");
        }

        // With deterministic latency and loss, both candidates have full
        // on-time probability; only feasible deadline urgency differs.
        let deterministic = quality(TransportKind::Quic, 100_000, 10_000, 0);
        assert!(utility(200, false, 0, deterministic) > utility(1_000, false, 0, deterministic));
    }

    #[test]
    fn impossible_or_unmeasured_alternates_have_zero_utility() {
        let no_alternate = VoiceRouteQuality::new(2, TransportKind::Udp, 80_000, 20_000, 8_000);
        let unmeasured_alternate = no_alternate.with_alternate_route(3, 100_000);
        let measured_alternate = quality(TransportKind::Quic, 100_000, 10_000, 10_000);

        for (name, score) in [
            ("no alternate", utility(500, false, 0, no_alternate)),
            (
                "unmeasured alternate",
                utility(500, false, 0, unmeasured_alternate),
            ),
            (
                "deadline impossible",
                utility(100, false, 0, measured_alternate),
            ),
            (
                "unsupported third copy",
                utility(500, false, 2, measured_alternate),
            ),
            (
                "zero original need",
                proactive_marginal_utility_micros(
                    0,
                    Duration::from_millis(500),
                    false,
                    0,
                    measured_alternate,
                ),
            ),
        ] {
            assert_eq!(score, 0, "{name}");
        }
    }

    #[test]
    fn marginal_utility_is_deterministic_for_one_immutable_input() {
        let captured = quality(TransportKind::Quic, 125_000, 12_345, 7_890);
        let expected = utility(430, true, 1, captured);
        assert!(expected > 0);
        for _ in 0..128 {
            assert_eq!(utility(430, true, 1, captured), expected);
        }
    }
}
