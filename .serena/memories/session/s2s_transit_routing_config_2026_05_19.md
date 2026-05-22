Implemented S2S overlay transit-routing config on 2026-05-19.

Config:
- `[s2s.overlay] route_transit_messages = true` default.
- `OverlayTuning.route_transit_messages` applies to `OverlayConfig` via `with_route_transit_messages`.
- `config.toml` documents the key.

Behavior:
- Local node advertises transit capability in LSAs via new proto field `LinkStateAdvert.transit_disabled = 9` (negative flag so legacy/absent means transit enabled).
- `LsaEntry.transit_disabled` round-trips through proto.
- `LsaEmitter` stores live `transit_disabled` state and can update it on hot reload.
- Dijkstra routing skips expanding non-transit nodes as intermediate vertices, but still allows them as destinations and allows the local node to originate normally.
- Inbound `OverlayData` forwarding has a guard using live emitter state as a stale-route/mixed-version backstop; local delivery is unaffected.
- `S2SManager::update_route_transit_messages` and `Server::reload_config` update/re-advertise the flag on config reload.

Tests added/updated:
- `config::tests::s2s_overlay_route_transit_messages_parses`
- `s2s::overlay::lsdb::store::tests::lsa_roundtrips_max_users` also checks transit flag.
- `s2s::overlay::routing::dijkstra::tests::non_transit_origin_can_be_destination_but_not_intermediate`
- `s2s::overlay::integration_tests::scenarios::transit_routing_disabled_nodes_are_not_route_intermediates`

Verification:
- Focused tests above pass.
- `cargo check --tests` passes, with existing Windows incremental compilation finalization warning: Access is denied.