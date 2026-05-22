# ACL SCC cache planning findings

- Current `ChannelRepository` already has `acl_cache: scc::HashCache<(u64, u32), BitFlags<ACLPermissions>>` plus `get_cached_permissions`, `cache_permissions`, channel/user invalidation helpers, and snapshot clear.
- `compute_permissions_for_client` currently does not use the repository cache; it always builds membership and calls pure `acl::evaluate_permission`.
- `evaluate_permission` should stay pure: it only receives channel/ancestor snapshots plus `ClientMembershipQuery`, and is benchmarked directly.
- Existing invalidation by exact channel id is not strict enough for inherited ACLs or channel parent moves: a parent ACL or `inherit_acl` change can affect descendants.
- User chose strict cache correctness: no known ACL-relevant mutation should leave stale effective permissions.
- Recommended implementation plan: use a generation/versioned SCC cache at `compute_permissions_for_client`, e.g. key `(acl_generation, session_u32_as_u64, channel_id)` or value includes generation; bump/clear on channel ACL/tree changes and client identity changes. Keep explicit cache APIs private/small and avoid caching superuser/missing-channel results unless intentionally decided.
- Client identity inputs affecting ACL: user_id, groups, tokens, certificate hash/verified state, IP. Current mutations observed in `handle_authenticate`, `Client::set_tokens`, and remote `apply_delta_to_global_state` for user_id/groups/tokens.
