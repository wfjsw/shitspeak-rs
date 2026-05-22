# S2S Channel Blob Replication

Implemented a third S2S replication mode for immutable content-addressed channel description blobs.

Key files:
- `src/protos/S2SReplication.proto`: `BlobMessage` oneof branch with `BlobFind`, `BlobOffer`, `BlobChunkReq`, `BlobChunk`.
- `src/s2s/replications/blob.rs`: blob runtime, deduped fetches by key, multi-provider chunk requests, hash validation before store, decay loop.
- `src/s2s/replications/mod.rs` and `topic.rs`: manager plumbing for blob topics alongside strict and owner modes.
- `src/s2s/mod.rs`: `ChannelBlobReplicationAdapter` registered as topic `channel_blobs`; `S2SManager::get_channel_blob` exposes client-handler fetch fallback.
- `src/client/handlers/request_blob.rs`: channel description RequestBlob tries local `ChannelBlobStore` first, then S2S blob fetch on miss.
- `src/blob_store.rs`: `ChannelBlobStore::keys()` for decay candidate enumeration.

Behavior:
- Blob content is immutable and addressed by lowercase SHA-1 hex. Downloaded bytes are stored only after recomputing and matching the requested key.
- Concurrent requests for the same key share one in-flight fetch and all waiters receive the same result.
- A requester broadcasts `BlobFind`, providers reply with `BlobOffer`, requester distributes chunk requests across up to `blob_max_parallel_peers`, and successful download makes the requester a future seed.
- Decay deletes locally stored channel blobs no longer referenced by any channel after `blob_unused_grace_ms`, scanned every `blob_decay_interval_ms`.
- Tunables live under `[s2s.replications]`: `blob_chunk_size`, `blob_request_timeout_ms`, `blob_offer_wait_ms`, `blob_retry_interval_ms`, `blob_max_parallel_peers`, `blob_decay_interval_ms`, `blob_unused_grace_ms`.

Verification at implementation time:
- `cargo check` passed; Windows reported non-fatal incremental compilation directory finalization warnings.
- Full `cargo test` ran: 256 passed, 3 pre-existing voice-format integration tests failed (`voice_tcp_protobuf_round_trips`, `voice_udp_format_matches_recipient_proto_version`, `voice_udp_protobuf_round_trips_and_decrypts`), unrelated to blob replication. New blob unit tests passed.