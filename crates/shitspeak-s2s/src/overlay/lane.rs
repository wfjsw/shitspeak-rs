use std::num::NonZeroU32;

/// Opt-in ordered overlay lane. Absence of a lane means unordered delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LaneId(NonZeroU32);

impl LaneId {
    pub const fn new(value: NonZeroU32) -> Self {
        Self(value)
    }

    pub fn get(self) -> u32 {
        self.0.get()
    }
}

impl TryFrom<u32> for LaneId {
    type Error = ();

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        NonZeroU32::new(value).map(Self).ok_or(())
    }
}

impl From<LaneId> for u32 {
    fn from(value: LaneId) -> Self {
        value.get()
    }
}
