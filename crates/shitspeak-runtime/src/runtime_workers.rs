#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeWorkerAllocation {
    main: usize,
    s2s: usize,
    acl_bulk: usize,
}

impl RuntimeWorkerAllocation {
    pub fn main(self) -> usize {
        self.main
    }

    pub fn s2s(self) -> usize {
        self.s2s
    }

    pub fn acl_bulk(self) -> usize {
        self.acl_bulk
    }
}

pub fn allocation_for_cpu_count(cpu_count: usize) -> RuntimeWorkerAllocation {
    let cpu_count = cpu_count.max(1);
    if cpu_count <= 4 {
        return RuntimeWorkerAllocation {
            main: cpu_count,
            s2s: cpu_count,
            acl_bulk: cpu_count,
        };
    }

    let s2s = (cpu_count / 3).max(4);
    RuntimeWorkerAllocation {
        main: (cpu_count - cpu_count / 3).max(4),
        s2s,
        acl_bulk: cpu_count.min(4),
    }
}

pub fn runtime_worker_allocation() -> RuntimeWorkerAllocation {
    let cpu_count = available_cpu_count();
    allocation_for_cpu_count(cpu_count)
}

pub fn all_cpu_workers() -> usize {
    available_cpu_count()
}

fn available_cpu_count() -> usize {
    std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(1)
}

#[cfg(test)]
mod tests {
    use super::{RuntimeWorkerAllocation, allocation_for_cpu_count};

    #[test]
    fn small_cpu_counts_give_each_runtime_the_cpu_count() {
        for cpu_count in 1..=4 {
            assert_eq!(
                allocation_for_cpu_count(cpu_count),
                RuntimeWorkerAllocation {
                    main: cpu_count,
                    s2s: cpu_count,
                    acl_bulk: cpu_count,
                }
            );
        }
        assert_eq!(allocation_for_cpu_count(0), allocation_for_cpu_count(1));
    }

    #[test]
    fn larger_cpu_counts_split_main_and_s2s_and_cap_acl_bulk() {
        for (cpu_count, main, s2s) in [
            (5, 4, 4),
            (6, 4, 4),
            (7, 5, 4),
            (8, 6, 4),
            (12, 8, 4),
            (15, 10, 5),
        ] {
            let allocation = allocation_for_cpu_count(cpu_count);
            assert_eq!(allocation.main(), main);
            assert_eq!(allocation.s2s(), s2s);
            assert_eq!(allocation.acl_bulk(), 4);
            assert!(allocation.main() >= 4);
            assert!(allocation.s2s() >= 4);
        }
    }

    #[test]
    fn worker_allocations_do_not_shrink_as_cpu_count_increases() {
        let mut previous = allocation_for_cpu_count(1);
        for cpu_count in 2..=128 {
            let current = allocation_for_cpu_count(cpu_count);
            assert!(current.main() >= previous.main());
            assert!(current.s2s() >= previous.s2s());
            assert!(current.acl_bulk() >= previous.acl_bulk());
            previous = current;
        }
    }

    #[test]
    fn all_cpu_workers_is_nonzero() {
        assert!(super::all_cpu_workers() >= 1);
    }
}
