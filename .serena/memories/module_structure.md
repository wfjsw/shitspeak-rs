# Module Structure

## Top-level modules (src/lib.rs)
- `acl` — ACL struct, ACLPermissions enum, evaluate_permission, channel_has_restriction
- `api` — API traits (Authenticator trait)
- `ban_repository` — BanEntry, BanOperation, BanRepository with WAL persistence
- `blob_store` — ChannelBlobStore (local) and SessionBlobStore (HTTP-backed cache)
- `channel_repository` — ChannelRepository with WAL, snapshot, versioned operations
- `channels` — Channel struct, ChannelPatch
- `client` — Client struct and all submodules (handlers, state, crypto, etc.)
- `client_certificate_verifier` — TLS client certificate verification
- `client_repository` — Session allocation/lookup (NOT channels)
- `codec_info` — CodecInfo struct for voice codec negotiation
- `config` — Config struct (loaded from config.toml)
- `constants` — App metadata, MTU, session ID limits
- `errors` — All error types
- `geoip` — GeoIP lookup (maxminddb)
- `messages` — Message enum, reader/writer, encoder modules, proc-macro
- `protocol_version` — ProtocolVersion newtype
- `proxy_protocol` — PROXY protocol v1/v2 parsing
- `s2s` — Server-to-server (stub, currently empty)
- `server` — Server struct, main accept loop
- `types` — NodeIdentifier type alias
- `voice` — Voice codec, ping, routing, UDP batching
- `voice_crypto` — CryptoProvider trait for voice encryption

## Client submodules (src/client/)
- `client.rs` — Client struct (main session object)
- `options.rs` — ClientOptions (per-client config)
- `group.rs` — Group membership evaluation (IP masks, tokens)
- `acl.rs` — compute_permissions_for_client
- `client_global_state.rs` — ClientGlobalState (shared, sync'd state)
- `client_local_state.rs` — ClientLocalState (per-connection state)
- `client_session_identifier.rs` — Composite 32-bit session ID (node_id 12 bits | local 20 bits)
- `client_stats.rs` — ClientStats (bandwidth tracking)
- `global_state_guard.rs` — GlobalStateWriteGuard (RAII write lock with version bump)
- `session_states.rs` — SessionStates (collection of all session states)
- `state_log.rs` — ClientStateLogEntry, ClientGlobalStateDelta, diff utilities
- `udp_state.rs` — UdpState (UDP socket/crypto state)
- `user_info.rs` — UserInfoExtended, Credential
- `user_version.rs` — UserVersion
- `voice_target.rs` — VoiceTarget, VoiceTargetChannel
- `crypt/` — CryptState, CryptoMode trait, Ocb2 implementation, CryptError
- `handlers/` — One handler function per message type (handle_authenticate, handle_acl, etc.)

## Message encoder modules (src/messages/encoder/)
One module per message type, each encoding a protobuf message from domain types.
