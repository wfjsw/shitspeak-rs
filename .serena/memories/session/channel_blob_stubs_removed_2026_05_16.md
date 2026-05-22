# Channel blob stale peer stubs removed

On 2026-05-16, checked ChannelBlobStore replication path. Active channel blob replication is through `src/s2s/mod.rs` `ChannelBlobReplicationAdapter`, registered under the `channel_blobs` topic with the S2S `BlobReplicable` runtime. The adapter uses `ChannelBlobStore::get`, `put`, `delete`, and `keys`; client fallback fetches through `S2SManager::get_channel_blob`.

`ChannelBlobStore::replicate_to` and `ChannelBlobStore::fetch_from_peer` in `src/blob_store.rs` were unused TODO stubs and were removed, along with the now-unused `std::net::SocketAddr` import.

Verification: `cargo fmt` and `cargo check` passed. Cargo emitted the known non-fatal Windows incremental compilation directory finalization warning (`Access is denied`).