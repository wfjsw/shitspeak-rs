use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicatedCommand {
    pub domain: String,
    pub verb: String,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum StrictStateMode {
    MajorityWritable,
    MinorityReadonly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalFrame<T> {
    pub index: u64,
    pub term: u64,
    pub payload: T,
}

#[derive(Debug, Clone)]
pub struct StrictState {
    pub mode: StrictStateMode,
    pub applied_index: u64,
}

impl Default for StrictState {
    fn default() -> Self {
        Self {
            mode: StrictStateMode::MajorityWritable,
            applied_index: 0,
        }
    }
}

impl StrictState {
    pub fn set_mode(&mut self, mode: StrictStateMode) {
        self.mode = mode;
    }

    pub fn can_accept_writes(&self) -> bool {
        self.mode == StrictStateMode::MajorityWritable
    }

    pub fn apply_command(&mut self, command: ReplicatedCommand) -> Result<WalFrame<ReplicatedCommand>, String> {
        if !self.can_accept_writes() {
            return Err("strict state is read-only in minority partition".to_owned());
        }

        self.applied_index = self.applied_index.saturating_add(1);
        Ok(WalFrame {
            index: self.applied_index,
            term: 0,
            payload: command,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command() -> ReplicatedCommand {
        ReplicatedCommand {
            domain: "channels".to_owned(),
            verb: "upsert".to_owned(),
            payload: vec![1, 2, 3],
        }
    }

    #[test]
    fn apply_command_increments_index() {
        let mut state = StrictState::default();
        let frame1 = state.apply_command(command()).expect("first command should apply");
        let frame2 = state.apply_command(command()).expect("second command should apply");
        assert_eq!(frame1.index, 1);
        assert_eq!(frame2.index, 2);
        assert_eq!(state.applied_index, 2);
    }

    #[test]
    fn minority_readonly_rejects_writes() {
        let mut state = StrictState::default();
        state.set_mode(StrictStateMode::MinorityReadonly);
        let err = state.apply_command(command()).expect_err("minority mode must reject writes");
        assert!(err.contains("read-only"));
    }
}
