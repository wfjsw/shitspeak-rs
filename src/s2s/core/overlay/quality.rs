use std::collections::HashMap;

use crate::s2s::core::NodeId;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NextHopQuality {
    pub success_percent: u8,
    pub avg_latency_ms: u32,
}

impl NextHopQuality {
    pub fn score(&self) -> i32 {
        i32::from(self.success_percent) * 10 - i32::try_from(self.avg_latency_ms).unwrap_or(i32::MAX)
    }
}

#[derive(Debug, Default)]
pub struct FanoutPlanner {
    quality: HashMap<NodeId, NextHopQuality>,
}

impl FanoutPlanner {
    pub fn new(quality: HashMap<NodeId, NextHopQuality>) -> Self {
        Self { quality }
    }

    pub fn plan(
        &self,
        fanout: HashMap<NodeId, Vec<NodeId>>,
    ) -> Vec<(NodeId, Vec<NodeId>)> {
        let mut ordered: Vec<(NodeId, Vec<NodeId>)> = fanout.into_iter().collect();
        ordered.sort_by(|(a, _), (b, _)| {
            let sa = self.quality.get(a).copied().unwrap_or_default().score();
            let sb = self.quality.get(b).copied().unwrap_or_default().score();
            sb.cmp(&sa).then_with(|| a.cmp(b))
        });
        ordered
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn planner_prefers_higher_quality_hops() {
        let planner = FanoutPlanner::new(HashMap::from([
            (10, NextHopQuality { success_percent: 98, avg_latency_ms: 12 }),
            (11, NextHopQuality { success_percent: 82, avg_latency_ms: 80 }),
        ]));

        let ordered = planner.plan(HashMap::from([
            (11, vec![2]),
            (10, vec![3]),
        ]));

        assert_eq!(ordered[0].0, 10);
        assert_eq!(ordered[1].0, 11);
    }
}
