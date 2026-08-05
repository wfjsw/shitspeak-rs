pub mod acl;
mod client;
pub mod client_global_state;
mod client_instance_id;
pub mod client_local_state;
pub mod client_session_identifier;
pub mod client_stats;
pub mod global_state_guard;
pub mod handlers;
pub mod options;
pub mod state_log;
pub mod user_info;
pub mod user_version;
pub mod visibility;
pub mod voice_target;

pub use client::{Client, ClientInstanceId, ClientTransportKind};
pub use client::{ClientOutboundMessage, ClientStateSubscription, OwnedMessageBatch};
pub(crate) use client::{
    DeferredSessionBlobResolution, PostAuthBaseline, RequestBlobQueueEnqueueError,
    VoiceTcpEnqueueResult,
};
pub(crate) use client_instance_id::next_client_instance_id;
pub use handlers::AsyncMessageHandlerExt;
