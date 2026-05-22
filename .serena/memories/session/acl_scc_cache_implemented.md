# ACL SCC cache implemented

Implemented strict SCC-backed effective permission caching at `client::acl::compute_permissions_for_client`.

Key design:
- `ChannelRepository` owns `acl_cache: scc::HashCache<(u64, u32), CachedAclPermissions>` where entries store `channel_acl_generation`, `client_acl_generation`, and permissions.
- `ChannelRepository::channel_acl_generation` bumps on ACL-effective channel changes: create, delete, `set_acls`, parent changes in update/edit, relevant remote/committed ops, and snapshot install. Link-only/name/position/description/max-users changes do not bump.
- `ClientGlobalState` has private `acl_generation`; it bumps on user_id, groups, and token changes. `Client::get_acl_generation()` exposes it for cache validation.
- `compute_permissions_for_client` bypasses superusers without caching, checks cache using both generations, snapshots channel+ancestors with stable channel ACL generation, computes via pure `evaluate_permission`, and caches only if channel/client generations are unchanged after computation. Missing-channel results are not cached.
- Added ACL scenario tests covering parent ACL descendant invalidation, inherit toggle, parent move, token update, group/admin/user_id generation, and missing-channel creation.

Verification:
- `cargo fmt --check` passed.
- `cargo check --lib` passed.
- `cargo test acl_cache --all-targets` passed: 6/6 focused cache tests.
- `cargo test integration_tests::scenarios::acls --lib` passed: 8/8 ACL scenario tests.
- `cargo test --lib` currently has unrelated reproducible voice protobuf format failures in `integration_tests::scenarios::voice::{voice_tcp_protobuf_round_trips, voice_udp_format_matches_recipient_proto_version, voice_udp_protobuf_round_trips_and_decrypts}`; ACL tests passed in that run.
