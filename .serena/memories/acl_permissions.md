# ACL & Permissions System

## Core Types (src/acl.rs)
- `ACL` struct — single ACL entry: apply_here, apply_subs, group, user_id, allow/deny permissions
- `ACLPermissions` enum — BitFlags<u32> via enumflags2 (with serde)
- `evaluate_permission(session_id, channel_id, perm)` — full permission evaluation with inheritance
- `channel_has_restriction(channel_id)` — check if channel or ancestors have any restrictive ACLs

## Client ACL (src/client/acl.rs)
- `compute_permissions_for_client(client, channel_id)` — compute effective permissions for a client in a channel

## Group Membership (src/client/group.rs)
- `MatchType` enum — Exact, Subnet, Token
- `IPMaskType` enum — IPv4, IPv6
- `TokenMatchType` enum — ExactMatch, PrefixMatch, SuffixMatch, SubstringMatch
- `ClientMembershipQuery` struct — query parameters for group membership
- `is_member_in_group(query)` — check if client matches group criteria
- `evaluate_group_string_match_type` — evaluate token match type

## ACL Cache
- ChannelRepository maintains `RwLock<HashMap<(session_id: u64, channel_id: u32), BitFlags<ACLPermissions>>>`
- Invalidated on SetAcls or channel move

## Benchmarks (benches/acl.rs)
- `bench_channel_has_restriction_for_loop` vs `bench_channel_has_restriction_iter_any`
- `bench_evaluate_permission`, `bench_evaluate_permission_deep`, `bench_evaluate_permission_mixed_inherit`
- `bench_acl_match_group`, `bench_acl_match_user`
