# Server-ID Scoping Implementation State - 2026-05-19

Runtime model remains server-id scoped repositories and entrypoint routing only.

Implemented/confirmed:
- `Client` carries private `server_id`; local auth can move a provisional client to auth-selected `server_id`, including IDs absent from config.
- `Config.server_entrypoints` maps extra listens/SNI names to server IDs; default listener remains default and SNI can route on the default TLS port.
- Hot config reload now reapplies `server_entrypoints`: SNI maps are refreshed, newly added listen bindings are TCP/UDP-bound and accept/drain tasks are spawned, and the target `server_id` is used as a plain scope even if it was absent from prior config.
- `main.rs` includes `mod web;` for the binary entrypoint.
- `ClientRepository` keys local/remote clients by `ScopedSessionId` and allocates local session-id pools independently per server ID.
- UDP client bindings are scoped by local UDP endpoint plus remote address for multi-listener UDP routing.
- `ChannelRepository` stores one shared repository keyed by `(server_id, channel_id)` and versions per server ID.
- Unknown/config-absent channel scopes synthesize/read channel `0` as root so auth-selected IDs can pass root ACL and receive a normal initial channel tree.
- Native auth now snapshots clients/versions after final server-id selection via `snapshot_with_versions_in_server`.
- S2S channel/blob topics use `channels:<server_id>` and `channel_blobs:<server_id>`, legacy names map to default.
- Client remote-op channel dependency buffering is scoped by op server ID while preserving per-origin log order.
- Public registration and UDP ping count only `DEFAULT_SERVER_ID`.

New tests added:
- `integration_tests::scenarios::auth::auth_selected_server_id_absent_from_config_scopes_client`
- `client_repository::tests::pending_remote_client_ops_wait_on_matching_server_channel_version`

Focused checks run and passing:
- `cargo check --tests` (passes with Windows incremental-finalization warning: Access denied)
- server entrypoint/SNI/config tests
- client/session/UDP scoping tests
- auth-selected config-absent server-id integration test
- `cargo test s2s::application --lib`

Latest continuation:
- Removed wording from memories that implied a separate record, lifecycle, or subsystem.
- Audited active native client broadcast replay; it uses `replay_since_in_server`, so the unreferenced `replay_client_log_gap` helper is stale but not on the active path.
