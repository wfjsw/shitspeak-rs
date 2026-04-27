pub type NodeId = u16;

mod hardening;
mod membership;
mod network;
mod ownership;
mod presence;
mod protocol;
mod routing;
mod swim;
mod transport;
mod transport_runtime;

pub use hardening::{FailureCircuitBreaker, FrameGuard, PeerRateLimiter};
pub use membership::{MemberRecord, MemberState, MembershipEvent, MembershipTable};
pub use network::{
	should_forward_with_loop_guard, OrderedDeliveryState, OverlayMessage, OverlayNetwork,
	PeerLink,
};
pub use ownership::{route_owned_operation, OwnedOperation, OwnershipRoute};
pub use presence::{NodePresenceDelta, NodePresenceMap, NodePresenceRecord, PresenceDigestEntry};
pub use protocol::{
	ApplicationLayer3Message, ClusterEnvelope, ClusterMessage, ConsensusLayer2Message,
	MessageMode,
};
pub use routing::{
	select_best_path, select_stable_path, LinkQualitySample, RouteCandidate, RouteClass,
	RoutePath, RouteSelectionPolicy, StableRouteState,
};
pub use swim::{ProbePlan, SwimMessage, SwimState};
pub use transport::{TransportCapabilities, TransportKind};
pub use transport_runtime::{
	choose_transport_pair, InboundEnvelope, OverlaySocketRuntime, SelectedTransport,
	TransportRuntimePolicy,
};
