#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolVersion {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
}


impl From<u32> for ProtocolVersion {
    fn from(version: u32) -> Self {
        Self {
            major: ((version >> 16) & 0xFF) as u64,
            minor: ((version >> 8) & 0xFF) as u64,
            patch: (version & 0xFF) as u64,
        }
    }
}

impl From<ProtocolVersion> for u32 {
    fn from(version: ProtocolVersion) -> Self {
        ((version.major.min(u16::MAX as u64) as u32) << 16)
            | ((version.minor.min(u8::MAX as u64) as u32) << 8)
            | (version.patch.min(u8::MAX as u64) as u32)
    }
}

impl From<u64> for ProtocolVersion {
    fn from(version: u64) -> Self {
        Self {
            major: ((version >> 48) & 0xFFFF) as u64,
            minor: ((version >> 32) & 0xFFFF) as u64,
            patch: ((version >> 16) & 0xFFFF) as u64,
        }
    }
}

impl From<ProtocolVersion> for u64 {
    fn from(version: ProtocolVersion) -> Self {
        ((version.major) << 48) | ((version.minor) << 32) | ((version.patch) << 16)
    }
}

impl ToString for ProtocolVersion {
    fn to_string(&self) -> String {
        format!("{}.{}.{}", self.major, self.minor, self.patch)
    }
}
