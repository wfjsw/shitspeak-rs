# Blob Store Design

## Common (src/blob_store.rs)
- `sha1_hex(data) -> String` — compute SHA-1 hex digest
- `blob_path(root, key) -> PathBuf` — compute filesystem path for a blob key

## ChannelBlobStore
- Persisted locally (filesystem-backed)
- Acts as primary storage (not a cache)
- Stores channel descriptions
- Propagated via S2S (stub: `replicate_to(peer, key)`)

## SessionBlobStore
- Session-scoped user textures and comments
- Backed by external HTTP server (blob store is a cache)
- Wiped/invalidated on server restart
- `fetch_from_remote(key, url)` for HTTP cache-miss fill
- `invalidate_session(session_id)` for cleanup on disconnect

## Design Decisions
- Always async (tokio async I/O, not spawn_blocking)
- SHA-1 keys (matches Mumble protocol wire format)
- Both implement common `BlobStore` trait (async get/put/exists/delete)
- S2S: ChannelBlobStore exposes `replicate_to` stub; channel WAL carries description_hash, blob bytes fetched separately
