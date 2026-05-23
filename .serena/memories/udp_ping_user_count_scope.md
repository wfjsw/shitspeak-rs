# UDP Ping User Count Scope

`Config::udp_ping_user_count_scope` keeps the global count source: `cluster` (default) uses `ClientRepository::len_in_server(status_server_id)` plus summed alive S2S-advertised `max_users`; `local` uses `ClientRepository::local_len_in_server(status_server_id)` plus local `Config::max_users`.

Per listen entrypoint, `ServerEntrypointConfig::udp_ping_status_server_id: Option<String>` selects which virtual server status an unauthenticated UDP ping on that port reports. If unset, the listen entrypoint reports its own `server_id`; the default listen port falls back to `DEFAULT_SERVER_ID`. Runtime mappings live in `EntrypointBindings::udp_ping_status_server_id_by_port`, are looked up in `Server::spawn_udp_drain`, and are passed to `Server::build_ping_response`.

Cluster max users are advertised via S2S overlay LSAs: `S2SOverlay.proto` `LinkStateAdvert.max_users = 8`, `LsaEntry.max_users`, `LsaEmitter.max_users`, `MembershipTable::alive_max_users()`, `OverlayNetwork::alive_max_users()`, and `S2SManager::cluster_max_users()`. `S2SManager::update_max_users()` updates the atomic and forces an LSA emit on config reload.

Sample config key in `config.toml`: `udp_ping_user_count_scope = "cluster"`. Per-port override example: `[[server_entrypoints]] udp_ping_status_server_id = "tenant-a"`. Focused tests cover config parsing and entrypoint ping-status mapping.