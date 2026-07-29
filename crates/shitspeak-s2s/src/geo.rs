use std::sync::Arc;

use parking_lot::RwLock;
use shitspeak_core::NodeGeo;

/// A node location that can be populated once after asynchronous discovery.
#[derive(Clone, Debug, Default)]
pub struct SharedNodeGeo {
    value: Arc<RwLock<Option<NodeGeo>>>,
}

impl SharedNodeGeo {
    pub fn new(value: Option<NodeGeo>) -> Self {
        Self {
            value: Arc::new(RwLock::new(value)),
        }
    }

    pub fn get(&self) -> Option<NodeGeo> {
        self.value.read().clone()
    }

    /// Stores `value` only when no location has been resolved yet.
    ///
    /// Returns whether this call populated the location.
    pub fn set_if_missing(&self, value: NodeGeo) -> bool {
        let mut current = self.value.write();
        if current.is_some() {
            return false;
        }
        *current = Some(value);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn geo(latitude: f64) -> NodeGeo {
        NodeGeo::new(latitude, 0.0, None, None, None, "test").expect("valid geo")
    }

    #[test]
    fn shared_node_geo_keeps_the_first_value() {
        let shared = SharedNodeGeo::default();

        assert!(shared.set_if_missing(geo(1.0)));
        assert!(!shared.set_if_missing(geo(2.0)));
        assert_eq!(shared.get().map(|value| value.latitude()), Some(1.0));
    }
}
