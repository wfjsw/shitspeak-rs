use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::membership::MemberState;
use super::NodeId;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SwimMessage {
    Ping {
        from: NodeId,
        target: NodeId,
        sequence: u64,
    },
    Ack {
        from: NodeId,
        target: NodeId,
        sequence: u64,
    },
    PingReq {
        from: NodeId,
        target: NodeId,
        via: NodeId,
        sequence: u64,
    },
    Suspect {
        subject: NodeId,
        incarnation: u64,
    },
    Alive {
        subject: NodeId,
        incarnation: u64,
        boot_id: String,
    },
    Dead {
        subject: NodeId,
        incarnation: u64,
    },
}

#[derive(Debug, Clone)]
pub struct ProbePlan {
    pub direct_target: Option<NodeId>,
    pub indirect_helpers: Vec<NodeId>,
}

#[derive(Debug, Clone)]
pub struct SwimState {
    local_node: NodeId,
    sequence: u64,
    suspect_nodes: HashMap<NodeId, u64>,
    pending_probes: HashMap<u64, (NodeId, u64)>,
}

impl SwimState {
    pub fn new(local_node: NodeId) -> Self {
        Self {
            local_node,
            sequence: 0,
            suspect_nodes: HashMap::new(),
            pending_probes: HashMap::new(),
        }
    }

    pub fn next_probe_plan(&mut self, alive_nodes: &[NodeId], indirect_count: usize) -> ProbePlan {
        self.sequence = self.sequence.saturating_add(1);

        let direct_target = alive_nodes
            .iter()
            .copied()
            .find(|candidate| *candidate != self.local_node);

        let indirect_helpers = alive_nodes
            .iter()
            .copied()
            .filter(|candidate| Some(*candidate) != direct_target && *candidate != self.local_node)
            .take(indirect_count)
            .collect();

        ProbePlan {
            direct_target,
            indirect_helpers,
        }
    }

    pub fn begin_direct_probe(&mut self, target: NodeId, now_ms: u64) -> u64 {
        self.sequence = self.sequence.saturating_add(1);
        self.pending_probes.insert(self.sequence, (target, now_ms));
        self.sequence
    }

    pub fn complete_probe(&mut self, sequence: u64) -> Option<NodeId> {
        self.pending_probes.remove(&sequence).map(|(target, _)| target)
    }

    pub fn overdue_probes(&self, now_ms: u64, timeout_ms: u64) -> Vec<(u64, NodeId)> {
        self.pending_probes
            .iter()
            .filter_map(|(seq, (target, started_ms))| {
                (now_ms.saturating_sub(*started_ms) >= timeout_ms).then_some((*seq, *target))
            })
            .collect()
    }

    pub fn build_indirect_requests(&self, sequence: u64, target: NodeId, via_nodes: &[NodeId]) -> Vec<SwimMessage> {
        via_nodes
            .iter()
            .copied()
            .map(|via| SwimMessage::PingReq {
                from: self.local_node,
                target,
                via,
                sequence,
            })
            .collect()
    }

    pub fn record_membership_state(&mut self, node_id: NodeId, state: MemberState, incarnation: u64) {
        if state == MemberState::Suspect {
            self.suspect_nodes.insert(node_id, incarnation);
        } else {
            self.suspect_nodes.remove(&node_id);
        }
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_plan_excludes_local_node() {
        let mut swim = SwimState::new(1);
        let plan = swim.next_probe_plan(&[1, 2, 3, 4], 2);
        assert_eq!(plan.direct_target, Some(2));
        assert!(!plan.indirect_helpers.contains(&1));
    }

    #[test]
    fn overdue_probe_detection_and_completion() {
        let mut swim = SwimState::new(1);
        let seq = swim.begin_direct_probe(3, 100);
        let overdue = swim.overdue_probes(250, 100);
        assert_eq!(overdue, vec![(seq, 3)]);
        assert_eq!(swim.complete_probe(seq), Some(3));
        assert!(swim.overdue_probes(300, 100).is_empty());
    }

    #[test]
    fn build_indirect_requests_targets_helpers() {
        let swim = SwimState::new(1);
        let reqs = swim.build_indirect_requests(7, 9, &[2, 3]);
        assert_eq!(reqs.len(), 2);
        assert!(matches!(
            reqs[0],
            SwimMessage::PingReq {
                from: 1,
                target: 9,
                via: 2,
                sequence: 7
            }
        ));
    }
}
