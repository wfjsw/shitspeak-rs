//! Link-state database. The single source of truth for both routing
//! topology and membership in Phase 2.

pub mod advert;
pub mod store;
pub mod sync;

pub use advert::{
    LsaEmitter, LsaFloodPacer, capture_boot_epoch, emit_once, flood_to_neighbors, handle_flood,
    spawn_emitter_task,
};
pub use store::{
    AdmissionResult, ApplicationServices, DistributionCapabilities, LinkAdvertised, LinkStateDb,
    LinkTransportAdvertised, LsaEntry, LsaFloor, OriginVersion, ReplicationServices,
    STRICT_REPLICATION_PROTOCOL_VERSION, STRICT_REPLICATION_TRANSIT_PROTOCOL_VERSION,
    spawn_floor_persister,
};
pub use sync::{
    full_pull, handle_request as handle_sync_request, handle_response as handle_sync_response,
    push_snapshot, spawn_anti_entropy,
};
