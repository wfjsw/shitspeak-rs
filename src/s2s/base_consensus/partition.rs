use serde::{Deserialize, Serialize};

use super::StrictStateMode;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum PartitionRole {
    Majority,
    Minority,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartitionPolicy {
    pub role: PartitionRole,
}

impl Default for PartitionPolicy {
    fn default() -> Self {
        Self {
            role: PartitionRole::Unknown,
        }
    }
}

impl PartitionPolicy {
    pub fn set_role(&mut self, role: PartitionRole) {
        self.role = role;
    }

    pub fn strict_state_mode(&self) -> StrictStateMode {
        match self.role {
            PartitionRole::Majority => StrictStateMode::MajorityWritable,
            PartitionRole::Minority | PartitionRole::Unknown => StrictStateMode::MinorityReadonly,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_unknown_and_readonly() {
        let policy = PartitionPolicy::default();
        assert_eq!(policy.role, PartitionRole::Unknown);
        assert_eq!(policy.strict_state_mode(), StrictStateMode::MinorityReadonly);
    }

    #[test]
    fn majority_maps_to_writable_mode() {
        let mut policy = PartitionPolicy::default();
        policy.set_role(PartitionRole::Majority);
        assert_eq!(policy.strict_state_mode(), StrictStateMode::MajorityWritable);
    }
}
