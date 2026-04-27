use super::NodeId;

#[derive(Debug, Clone)]
pub struct OwnedOperation {
    pub operation_id: u64,
    pub owner_node: NodeId,
    pub domain: String,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum OwnershipRoute {
    ExecuteLocal,
    ForwardToOwner(NodeId),
}

pub fn route_owned_operation(local_node: NodeId, op: &OwnedOperation) -> OwnershipRoute {
    if op.owner_node == local_node {
        OwnershipRoute::ExecuteLocal
    } else {
        OwnershipRoute::ForwardToOwner(op.owner_node)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_to_local_when_owner_matches() {
        let op = OwnedOperation {
            operation_id: 1,
            owner_node: 7,
            domain: "acl".to_owned(),
            payload: vec![],
        };
        assert!(matches!(route_owned_operation(7, &op), OwnershipRoute::ExecuteLocal));
    }

    #[test]
    fn routes_to_owner_when_remote() {
        let op = OwnedOperation {
            operation_id: 2,
            owner_node: 9,
            domain: "ban".to_owned(),
            payload: vec![],
        };
        assert!(matches!(
            route_owned_operation(7, &op),
            OwnershipRoute::ForwardToOwner(9)
        ));
    }
}
