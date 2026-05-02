//! Link-state database. The single source of truth for both routing
//! topology and membership in Phase 2.

pub mod advert;
pub mod store;
pub mod sync;

pub use advert::{
    capture_boot_epoch, emit_once, flood_to_neighbors, handle_flood, spawn_emitter_task, LsaEmitter,
};
pub use store::{
    spawn_floor_persister, AdmissionResult, LinkAdvertised, LinkStateDb, LsaEntry, LsaFloor,
    OriginVersion,
};
pub use sync::{
    full_pull, handle_request as handle_sync_request, handle_response as handle_sync_response,
    spawn_anti_entropy,
};
