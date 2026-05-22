# Server-ID Scoped Channels, Clients, And Sessions

The runtime model is a string `server_id` scope used by repositories and routing:

- Config maps client entrypoints such as ports and SNI names to a `server_id`.
- Auth may return any `server_id`; config does not limit valid auth-selected IDs.
- Each client carries its current `server_id`.
- Channel identity is scoped by `(server_id, channel_id)` in one shared `ChannelRepository`.
- Client identity and presence are scoped by `(server_id, session_id)` in one shared `ClientRepository`.
- Each `server_id` has an independent numeric session-ID pool.
- Channel ID `0` exists independently per `server_id`.
- Public registration and UDP ping status report only `default`.

S2S channel replication should behave as plain channel repository replication with a topic scope:

- Topics `channels:<server_id>` and `channel_blobs:<server_id>` map to that repository scope.
- Legacy `channels` and `channel_blobs` map to `default`.
- Replicated channel/blob data is stored under its `server_id` scope in the shared repositories.
- S2S channel state works for any `server_id`, even if absent from config.
- Remote discovery alone does not alter local listeners, SNI mappings, auth routes, public registration entries, or web routing entries.

Queries, broadcasts, subscriptions, text routing, voice routing, ACL/cache lookup, channel operations, snapshots, catch-up, blob reference tracking, and blob serving/fetching must all filter by `server_id` where they operate on channel/client state.
