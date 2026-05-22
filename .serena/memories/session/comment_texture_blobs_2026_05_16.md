# Comment and Texture Blobs Implemented

Implemented session comment/texture blob support for direct UserState uploads and auth-provided blobs.

Key behavior:
- `SessionBlobStore` now supports `put_content(data) -> sha1`, `get_cached(key)`, and `fetch_and_cache(url) -> (sha1, bytes)` in addition to URL-backed `get(key, url)`.
- `handle_user_state` stores non-empty self `comment` and `texture` payloads in `SessionBlobStore`, records only the SHA-1 hash in `ClientGlobalState`, and enforces configured max text/image sizes. Empty comment/texture clears the corresponding blob.
- Non-self UserState self-only fields (`self_mute`, `self_deaf`, `texture`, plugin fields, `recording`) are protocol violations. Non-self comment changes can only clear and require root `Move` permission.
- Registered users also call authenticator persistence hooks: `set_user_comment`, `set_user_texture`; login seeds hashes from `get_user_comment`/`get_user_texture` when no auth URL exists, and from `texture_url`/`comment_url` via `fetch_and_cache` when URLs exist.
- `RequestBlob` serves session blobs from local cache when no URL is present and fixed the texture reply typo that previously populated `comment_hash` with the texture hash.
- `ClientGlobalState::clear_*_blob` now records deltas. `ClientStateLogEntry::to_message` emits empty `comment`/`texture` fields for blob clears, because absent hash fields cannot represent a clear on the wire.

Tests:
- `cargo test self_actions -- --nocapture` passes 4 self-action tests, including comment/texture blob broadcast, request, and clear coverage.
- `cargo check` passes. On Windows, cargo may print non-fatal incremental compilation finalization warnings: `Access is denied` under `target/debug/incremental`.
