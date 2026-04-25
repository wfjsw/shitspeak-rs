# Message Handling Architecture

## Message Flow
1. TCP stream → `ReadMessageExt` (reads varint length prefix + protobuf)
2. `Message` enum — one variant per Mumble message type
3. `AsyncMessageHandlerExt` trait on `Arc<Box<Client>>` — dispatches to handler functions
4. Handler functions in `src/client/handlers/` — one per message type
5. Handler may produce response messages via `WriteMessageExt`

## Message Enum (src/messages/message.rs)
- `Message` enum with variants for all Mumble protocol message types
- Implements `Display`

## Reader/Writer (src/messages/)
- `ReadMessageExt` trait — async read of varint-length-prefixed protobuf messages
- `WriteMessageExt` trait — async write of varint-length-prefixed protobuf messages
- Implemented for `T: AsyncRead + Unpin` and `T: AsyncWrite + Unpin` respectively

## Encoder Modules (src/messages/encoder/)
- One module per message type
- Each encodes domain types → protobuf message types
- Modules: acl, authenticate, ban_list, channel_remove, channel_state, codec_version, context_action, context_action_modify, crypt_setup, permission_denied, permission_query, ping, query_users, reject, reject_type, request_blob, server_config, server_sync, suggest_config, text_message, user_list, user_remove, user_state, user_stats, version, voice_target

## Proc Macro (src/messages/macros/)
- `message_conversion` proc macro — derives conversion between Message enum and protobuf types
- `is_vec_u8` helper

## Handler Functions (src/client/handlers/)
- `handle_authenticate` — authentication flow
- `handle_acl` — ACL updates
- `handle_ban_list` — ban list queries
- `handle_channel_remove` — channel removal
- `handle_channel_state` — channel state queries/updates
- `handle_crypt_setup` — voice crypto setup
- `handle_permission_query` — permission queries
- `handle_ping` — TCP ping
- `handle_query_users` — user queries
- `handle_request_blob` — blob requests
- `handle_text_message` — text messages (with subtree collection)
- `handle_udp_tunnel` — UDP tunnel (in mod.rs)
- `handle_user_list` — user list queries
- `handle_user_remove` — user removal
- `handle_user_state` — user state updates
- `handle_user_stats` — user statistics
- `handle_version` — version exchange
- `handle_voice_target` — voice target setup
