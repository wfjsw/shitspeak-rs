//! Nonnegative least-squares cost surface and bounded integer optimization.
//! Times are microseconds; fanout is scaled by 1024 for numerical conditioning.

const FEATURES: usize = 7;

#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) struct CostModel {
    sequential: [f64; 2],
    parallel: [f64; FEATURES],
    workers: usize,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Sample {
    pub(super) fanout: usize,
    pub(super) partitions: usize,
    pub(super) micros: f64,
}

fn features(n: usize, p: usize) -> [f64; FEATURES] {
    let n = n as f64 / 1024.0;
    let p = p as f64;
    // Dispatch, serial work, critical encryption path, per-partition work,
    // tree-merge work, excessive partition density, and encryption cost growth
    // as larger working sets exceed cache capacity.
    [
        1.0,
        n,
        n / p,
        p,
        n * p.log2(),
        p * p / n,
        n * (1.0 + n).log2() / p,
    ]
}

impl CostModel {
    pub(super) fn fit(samples: &[Sample], workers: usize) -> Result<Self, String> {
        let sequential: Vec<_> = samples
            .iter()
            .filter(|s| s.partitions == 1)
            .map(|s| ([1.0, s.fanout as f64 / 1024.0], s.micros))
            .collect();
        let parallel: Vec<_> = samples
            .iter()
            .filter(|s| s.partitions >= 2)
            .map(|s| (features(s.fanout, s.partitions), s.micros))
            .collect();
        Ok(Self {
            sequential: fit_nonnegative(&sequential)?,
            parallel: fit_nonnegative(&parallel)?,
            workers,
        })
    }

    pub(super) fn predict(self, fanout: usize, partitions: usize) -> f64 {
        if partitions == 1 {
            self.sequential[0] + self.sequential[1] * fanout as f64 / 1024.0
        } else {
            features(fanout, partitions)
                .iter()
                .zip(self.parallel)
                .map(|(x, b)| x * b)
                .sum()
        }
    }

    pub(super) fn choose(self, fanout: usize, available: usize) -> usize {
        if fanout < 2 {
            return 1;
        }
        let best = (2..=available.min(self.workers).min(fanout)).min_by(|&a, &b| {
            self.predict(fanout, a)
                .total_cmp(&self.predict(fanout, b))
                .then(a.cmp(&b))
        });
        match best {
            Some(p) if self.predict(fanout, p) <= self.predict(fanout, 1) * 0.95 => p,
            _ => 1,
        }
    }

    pub(super) fn workers(self) -> usize {
        self.workers
    }
}

// Cyclic coordinate descent on scaled, relative-error least squares. All
// coefficients are constrained to be nonnegative, so noise cannot create
// negative dispatch costs or reward unlimited fragmentation. Huber reweighting
// limits the influence of scheduler outliers.
fn fit_nonnegative<const N: usize>(rows: &[([f64; N], f64)]) -> Result<[f64; N], String> {
    if rows.len() < N
        || rows
            .iter()
            .any(|(x, y)| !y.is_finite() || *y <= 0.0 || x.iter().any(|v| !v.is_finite()))
    {
        return Err("insufficient or invalid calibration samples".into());
    }
    let scales: [f64; N] =
        std::array::from_fn(|j| rows.iter().map(|(x, _)| x[j]).fold(1.0, f64::max));
    let mut beta = [0.0; N];
    let mut weights = vec![1.0; rows.len()];
    for _ in 0..4 {
        for _ in 0..4000 {
            let mut change: f64 = 0.0;
            for j in 0..N {
                let mut numerator = 0.0;
                let mut denominator = 1e-12;
                for ((x, y), weight) in rows.iter().zip(&weights) {
                    let prediction: f64 = (0..N).map(|k| x[k] / scales[k] * beta[k]).sum();
                    let v = x[j] / scales[j];
                    let w = weight / (y * y);
                    numerator += w * v * (y - prediction + v * beta[j]);
                    denominator += w * v * v;
                }
                let next = (numerator / denominator).max(0.0);
                change = change.max((next - beta[j]).abs() / (1.0 + beta[j]));
                beta[j] = next;
            }
            if change < 1e-7 {
                break;
            }
        }
        for ((x, y), weight) in rows.iter().zip(&mut weights) {
            let prediction: f64 = (0..N).map(|k| x[k] / scales[k] * beta[k]).sum();
            *weight = (0.15 / ((prediction - y) / y).abs().max(0.15)).min(1.0);
        }
    }
    Ok(std::array::from_fn(|j| beta[j] / scales[j]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic() -> Vec<Sample> {
        [64, 128, 256, 512, 1024, 2048, 4096, 8192]
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
            .collect()
    }

    #[test]
    fn fitted_optimizer_finds_interior_optima_and_switches_with_fanout() {
        let model = CostModel::fit(&synthetic(), 40).unwrap();
        assert_eq!(model.choose(64, 40), 1);
        assert_eq!(model.choose(2048, 40), 5);
        assert_eq!(model.choose(4096, 40), 7);
        assert_eq!(model.choose(8192, 40), 10);
        // Verify unseen fanouts against the generating objective, including
        // the sequential boundary and all integer partition candidates.
        for n in 65..4096 {
            let chosen = model.choose(n, 40);
            let exact = |p: usize| {
                if p == 1 {
                    0.5 * n as f64
                } else {
                    50.0 + 8.192 * p as f64 + 0.1 * n as f64 / p as f64
                }
            };
            let best = (2..=40)
                .min_by(|&a, &b| exact(a).total_cmp(&exact(b)))
                .unwrap();
            let expected = if exact(best) <= exact(1) * 0.95 {
                best
            } else {
                1
            };
            assert!(
                exact(chosen) <= exact(expected) * 1.01,
                "n={n} chosen={chosen} expected={expected}"
            );
        }
    }

    #[test]
    fn respects_worker_limits_and_rejects_invalid_samples() {
        let model = CostModel::fit(&synthetic(), 40).unwrap();
        assert_eq!(model.choose(0, 40), 1);
        assert_eq!(model.choose(2048, 1), 1);
        assert_eq!(model.choose(8192, 3), 3);
        assert!(CostModel::fit(&[], 40).is_err());
    }

    #[test]
    fn two_worker_pool_still_learns_a_crossover() {
        let samples: Vec<_> = synthetic()
            .into_iter()
            .filter(|s| s.partitions <= 2)
            .collect();
        let model = CostModel::fit(&samples, 2).unwrap();
        assert_eq!(model.choose(64, 2), 1);
        assert_eq!(model.choose(2048, 2), 2);
    }

    #[test]
    fn isolated_scheduler_outlier_does_not_erase_the_parallel_optimum() {
        let mut samples = synthetic();
        samples
            .iter_mut()
            .find(|s| s.fanout == 2048 && s.partitions == 5)
            .unwrap()
            .micros *= 20.0;
        let model = CostModel::fit(&samples, 40).unwrap();
        assert_eq!(model.choose(2048, 40), 5);
        assert!(model.parallel.iter().all(|&c| c >= 0.0));
        assert!((model.predict(2048, 5) - 131.92).abs() < 5.0);
    }

    #[test]
    fn sequential_is_a_real_candidate_and_requires_five_percent_gain() {
        let model = CostModel {
            sequential: [100.0, 0.0],
            parallel: [96.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
            workers: 40,
        };
        assert_eq!(model.choose(2048, 40), 1);
        let model = CostModel {
            parallel: [95.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
            ..model
        };
        assert_eq!(model.choose(2048, 40), 2);
    }

    #[test]
    fn nonfinite_training_values_are_rejected() {
        let mut samples = synthetic();
        samples[0].micros = f64::NAN;
        assert!(CostModel::fit(&samples, 40).is_err());
    }

    #[test]
    fn learns_encryption_cost_growth_with_larger_working_sets() {
        let cost = |n: usize, p: usize| {
            if p == 1 {
                return 0.9 * n as f64;
            }
            50.0 + 20.0 * p as f64
                + (0.5 + 0.25 * (1.0 + n as f64 / 1024.0).log2()) * n as f64 / p as f64
        };
        let samples: Vec<_> = [64, 128, 256, 512, 1024, 2048, 4096, 8192]
            .into_iter()
            .flat_map(|n| {
                (1..=40).map(move |p| Sample {
                    fanout: n,
                    partitions: p,
                    micros: cost(n, p),
                })
            })
            .collect();
        let model = CostModel::fit(&samples, 40).unwrap();
        let expected = (2..=40)
            .min_by(|&a, &b| cost(8192, a).total_cmp(&cost(8192, b)))
            .unwrap();
        assert_eq!(model.choose(8192, 40), expected);
    }
}
