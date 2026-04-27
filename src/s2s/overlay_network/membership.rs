use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::NodeId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemberState {
    Alive,
    Suspect,
    Dead,
    Left,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberRecord {
    pub node_id: NodeId,
    pub state: MemberState,
    pub incarnation: u64,
    pub last_seen_ms: u64,
    pub boot_id: String,
}

#[derive(Debug, Clone)]
pub enum MembershipEvent {
    StateChanged {
        node_id: NodeId,
        from: MemberState,
        to: MemberState,
    },
    NodeRestarted {
        node_id: NodeId,
        previous_boot_id: String,
        new_boot_id: String,
    },
}

#[derive(Debug, Clone)]
pub struct MembershipTable {
    members: HashMap<NodeId, MemberRecord>,
    tombstones: HashMap<NodeId, u64>,
    pub suspect_timeout_ms: u64,
    pub dead_timeout_ms: u64,
}

impl MembershipTable {
    pub fn new(suspect_timeout_ms: u64, dead_timeout_ms: u64) -> Self {
        Self {
            members: HashMap::new(),
            tombstones: HashMap::new(),
            suspect_timeout_ms,
            dead_timeout_ms,
        }
    }

    pub fn upsert_alive(&mut self, node_id: NodeId, boot_id: String, now_ms: u64) -> Vec<MembershipEvent> {
        let mut events = Vec::new();
        match self.members.get_mut(&node_id) {
            Some(record) => {
                if record.boot_id != boot_id {
                    events.push(MembershipEvent::NodeRestarted {
                        node_id,
                        previous_boot_id: record.boot_id.clone(),
                        new_boot_id: boot_id.clone(),
                    });
                    record.boot_id = boot_id;
                    record.incarnation = record.incarnation.saturating_add(1);
                }

                if record.state != MemberState::Alive {
                    let from = record.state;
                    record.state = MemberState::Alive;
                    events.push(MembershipEvent::StateChanged {
                        node_id,
                        from,
                        to: MemberState::Alive,
                    });
                }

                record.last_seen_ms = now_ms;
            }
            None => {
                self.tombstones.remove(&node_id);
                self.members.insert(
                    node_id,
                    MemberRecord {
                        node_id,
                        state: MemberState::Alive,
                        incarnation: 1,
                        last_seen_ms: now_ms,
                        boot_id,
                    },
                );
            }
        }

        events
    }

    pub fn mark_left(&mut self, node_id: NodeId) -> Option<MembershipEvent> {
        let record = self.members.get_mut(&node_id)?;
        if record.state == MemberState::Left {
            return None;
        }
        let from = record.state;
        record.state = MemberState::Left;
        Some(MembershipEvent::StateChanged {
            node_id,
            from,
            to: MemberState::Left,
        })
    }

    pub fn tick(&mut self, now_ms: u64) -> Vec<MembershipEvent> {
        let mut events = Vec::new();
        for record in self.members.values_mut() {
            let elapsed = now_ms.saturating_sub(record.last_seen_ms);
            match record.state {
                MemberState::Alive if elapsed >= self.suspect_timeout_ms => {
                    let from = record.state;
                    record.state = MemberState::Suspect;
                    events.push(MembershipEvent::StateChanged {
                        node_id: record.node_id,
                        from,
                        to: MemberState::Suspect,
                    });
                }
                MemberState::Suspect if elapsed >= self.dead_timeout_ms => {
                    let from = record.state;
                    record.state = MemberState::Dead;
                    self.tombstones.insert(record.node_id, now_ms);
                    events.push(MembershipEvent::StateChanged {
                        node_id: record.node_id,
                        from,
                        to: MemberState::Dead,
                    });
                }
                _ => {}
            }
        }

        events
    }

    pub fn get(&self, node_id: NodeId) -> Option<&MemberRecord> {
        self.members.get(&node_id)
    }

    pub fn alive_nodes(&self) -> Vec<NodeId> {
        self.members
            .values()
            .filter(|r| r.state == MemberState::Alive)
            .map(|r| r.node_id)
            .collect()
    }

    pub fn tombstones(&self) -> &HashMap<NodeId, u64> {
        &self.tombstones
    }

    pub fn purge_expired_tombstones(&mut self, now_ms: u64, expire_after_ms: u64) -> Vec<NodeId> {
        let mut removed = Vec::new();
        self.tombstones.retain(|node_id, recorded_ms| {
            let keep = now_ms.saturating_sub(*recorded_ms) < expire_after_ms;
            if !keep {
                removed.push(*node_id);
            }
            keep
        });
        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upsert_creates_alive_member() {
        let mut table = MembershipTable::new(10, 20);
        let events = table.upsert_alive(1, "boot-a".to_owned(), 100);
        assert!(events.is_empty());
        let record = table.get(1).expect("member should exist");
        assert_eq!(record.state, MemberState::Alive);
    }

    #[test]
    fn upsert_with_new_boot_id_emits_restart_event() {
        let mut table = MembershipTable::new(10, 20);
        table.upsert_alive(1, "boot-a".to_owned(), 10);
        let events = table.upsert_alive(1, "boot-b".to_owned(), 20);
        assert!(events.iter().any(|e| matches!(
            e,
            MembershipEvent::NodeRestarted { node_id: 1, .. }
        )));
    }

    #[test]
    fn tick_transitions_alive_to_suspect_to_dead() {
        let mut table = MembershipTable::new(10, 20);
        table.upsert_alive(3, "boot".to_owned(), 0);

        let suspect = table.tick(10);
        assert!(suspect.iter().any(|e| matches!(
            e,
            MembershipEvent::StateChanged { to: MemberState::Suspect, .. }
        )));

        let dead = table.tick(20);
        assert!(dead.iter().any(|e| matches!(
            e,
            MembershipEvent::StateChanged { to: MemberState::Dead, .. }
        )));
        assert!(table.tombstones().contains_key(&3));
    }

    #[test]
    fn purge_expired_tombstones_removes_only_old_entries() {
        let mut table = MembershipTable::new(1, 2);
        table.upsert_alive(8, "boot".to_owned(), 0);
        table.tick(2);
        table.tick(3);
        let removed = table.purge_expired_tombstones(200, 100);
        assert_eq!(removed, vec![8]);
    }
}
