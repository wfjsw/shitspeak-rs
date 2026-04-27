use serde::{Deserialize, Serialize};

use crate::s2s::overlay_network::NodeId;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum RaftRole {
    Follower,
    Candidate,
    Leader,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub index: u64,
    pub term: u64,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestVoteRequest {
    pub term: u64,
    pub candidate_id: NodeId,
    pub last_log_index: u64,
    pub last_log_term: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestVoteResponse {
    pub term: u64,
    pub vote_granted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppendEntriesRequest {
    pub term: u64,
    pub leader_id: NodeId,
    pub prev_log_index: u64,
    pub prev_log_term: u64,
    pub entries: Vec<LogEntry>,
    pub leader_commit: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppendEntriesResponse {
    pub term: u64,
    pub success: bool,
    pub match_index: u64,
}

#[derive(Debug, Clone)]
pub enum RaftEvent {
    BecameLeader { term: u64 },
    BecameFollower { term: u64 },
    CommitAdvanced { commit_index: u64 },
}

#[derive(Debug, Clone)]
pub struct RaftCore {
    pub local_node: NodeId,
    pub current_term: u64,
    pub role: RaftRole,
    pub commit_index: u64,
    pub last_applied: u64,
}

impl RaftCore {
    pub fn new(local_node: NodeId) -> Self {
        Self {
            local_node,
            current_term: 0,
            role: RaftRole::Follower,
            commit_index: 0,
            last_applied: 0,
        }
    }

    pub fn update_term(&mut self, term: u64) -> Option<RaftEvent> {
        if term <= self.current_term {
            return None;
        }

        self.current_term = term;
        self.role = RaftRole::Follower;
        Some(RaftEvent::BecameFollower { term })
    }

    pub fn become_candidate(&mut self) {
        self.current_term = self.current_term.saturating_add(1);
        self.role = RaftRole::Candidate;
    }

    pub fn become_leader(&mut self) -> RaftEvent {
        self.role = RaftRole::Leader;
        RaftEvent::BecameLeader {
            term: self.current_term,
        }
    }

    pub fn advance_commit(&mut self, commit_index: u64) -> Option<RaftEvent> {
        if commit_index <= self.commit_index {
            return None;
        }

        self.commit_index = commit_index;
        Some(RaftEvent::CommitAdvanced { commit_index })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn term_update_requires_increase() {
        let mut raft = RaftCore::new(7);
        assert!(raft.update_term(0).is_none());
        let event = raft.update_term(2);
        assert!(matches!(event, Some(RaftEvent::BecameFollower { term: 2 })));
        assert_eq!(raft.current_term, 2);
        assert_eq!(raft.role, RaftRole::Follower);
    }

    #[test]
    fn candidate_and_leader_transitions_work() {
        let mut raft = RaftCore::new(3);
        raft.become_candidate();
        assert_eq!(raft.current_term, 1);
        assert_eq!(raft.role, RaftRole::Candidate);

        let event = raft.become_leader();
        assert!(matches!(event, RaftEvent::BecameLeader { term: 1 }));
        assert_eq!(raft.role, RaftRole::Leader);
    }

    #[test]
    fn commit_advances_monotonically() {
        let mut raft = RaftCore::new(1);
        assert!(raft.advance_commit(0).is_none());
        let event = raft.advance_commit(5);
        assert!(matches!(event, Some(RaftEvent::CommitAdvanced { commit_index: 5 })));
        assert_eq!(raft.commit_index, 5);
        assert!(raft.advance_commit(4).is_none());
    }
}
