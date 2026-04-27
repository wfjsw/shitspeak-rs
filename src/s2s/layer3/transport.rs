use super::{OwnerOrderedFrame, VersionVector};
use crate::s2s::WalFrame;

pub trait StrictOverlayCatchupTransport {
    type Error;

    fn broadcast_strict_frame(&self, frame: &WalFrame<Vec<u8>>) -> Result<(), Self::Error>;
    fn fetch_strict_frames_since(
        &self,
        applied_index: u64,
    ) -> Result<Vec<WalFrame<Vec<u8>>>, Self::Error>;
}

pub trait OwnerOverlayCatchupTransport {
    type Error;

    fn broadcast_owner_frame(&self, frame: &OwnerOrderedFrame<Vec<u8>>) -> Result<(), Self::Error>;
    fn fetch_owner_frames_since(
        &self,
        version_vector: &VersionVector,
    ) -> Result<Vec<OwnerOrderedFrame<Vec<u8>>>, Self::Error>;
}
