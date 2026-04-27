use crate::s2s::overlay_network::NodeId;

pub trait OwnerOrderedStateEngine {
    type Error;

    fn apply_origin_committed(
        &mut self,
        origin_node: NodeId,
        origin_version: u64,
        payload: &[u8],
    ) -> Result<(), Self::Error>;
}
