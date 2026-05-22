# UDP Ping User Count Scope

Added `udp_ping_user_count_scope` to `Config` with enum `UdpPingUserCountScope` (`cluster` default, `local` alternate). UDP ping responses now branch in `Server::build_ping_response`: `cluster` uses `ClientRepository::len()` and summed alive S2S-advertised `max_users`; `local` uses `ClientRepository::local_len()` and local `Config::max_users`.

Cluster max users are advertised via S2S overlay LSAs: `S2SOverlay.proto` `LinkStateAdvert.max_users = 8`, `LsaEntry.max_users`, `LsaEmitter.max_users`, `MembershipTable::alive_max_users()`, `OverlayNetwork::alive_max_users()`, and `S2SManager::cluster_max_users()`. `S2SManager::update_max_users()` updates the atomic and forces an LSA emit on config reload.

Sample config key in `config.toml`: `udp_ping_user_count_scope = "cluster"`. Focused tests added for config parsing/default and LSA/membership max-user summing.