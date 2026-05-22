# ACL Message Handler Review

Date: 2026-05-17

This report audits incoming client message handlers for missing or incorrect ACL checks against upstream Mumble/Murmur behavior. It should be read together with the ACL evaluator audit: several handlers call `compute_permissions_for_client`, but that evaluator is currently not Mumble-compatible, so even checks that are present can return the wrong answer.

## Reference Baseline

Upstream references used for comparison:

- `D:\mumble\src\ACL.cpp`
  - `ChanACL::effectivePermissions`: default permissions, root-to-leaf ordered ACL evaluation, special `Traverse`/`Write` behavior, and superuser exclusions.
  - Key lines from local checkout: `103-232`.
- `D:\mumble\src\murmur\Messages.cpp`
  - Incoming message handlers and per-message permission gates.
- `D:\mumble\src\murmur\Server.cpp`
  - Voice routing, whisper target checks, permission query fanout, and suppress refresh.

Important upstream semantics:

- `Write` implies most non-voice permissions after evaluation: `Traverse`, `Enter`, `MuteDeafen`, `Move`, `MakeChannel`, `LinkChannel`, `TextMessage`, `MakeTempChannel`, and `Listen`; root `Write` also implies root-only admin bits.
- SuperUser gets all permissions except `Speak` and `Whisper`.
- `TextMessage` is checked against every target channel, tree root, tree descendant, and direct target user's current channel.
- Whisper/voice-target delivery checks sender `Whisper` on target channels.
- `UserStats` full details require self or root `Ban`; otherwise caller needs `Enter` on the target user's channel.
- `QueryUsers` requires `Write` on at least one channel.
- `UserList` requires root `Register`.

## Systemic Blocker

Before handler-specific work, `src/acl.rs` needs correction. The current evaluator walks target-to-root, accumulates all allow/deny bits, and returns `allowed & !denied`. That makes parent denies globally sticky and does not implement Mumble's ordered root-to-leaf overwrite semantics, `Traverse` path gate, `Write` implication, or root-only admin-bit handling.

Every handler below that says "check exists" still depends on fixing this evaluator.

## Critical Findings

### 1. `PermissionQuery` Returns a Hard-Coded Full Mask

Local code:

- `src/client/handlers/permission_query.rs:29` computes permissions.
- `src/client/handlers/permission_query.rs:41-42` comments out `perms.bits()` and returns `0x1F0FFF`.

Impact:

- Clients are told they have broad permissions regardless of actual ACLs.
- UI can expose unauthorized operations and cache incorrect permissions.

Expected Mumble behavior:

- `Messages.cpp:2317-2326` calls `sendClientPermission(uSource, c, true)`.
- `Server.cpp:2095-2120` sends the computed cached permission value.

Recommended fix:

- Return `permissions: Some(perms.bits())`.
- Add a regression test that denies `Write` or `TextMessage` and verifies `PermissionQuery` reports the denied bit as absent.

### 2. `TextMessage` Has No `TextMessage` ACL Enforcement

Local code:

- `src/client/handlers/text_message.rs:47-78` relays direct, channel, and tree text messages without computing permissions.

Impact:

- Any authenticated user can send channel/tree/direct text messages into channels where they lack `TextMessage`.
- Tree messages are especially broad because subtree traversal also skips ACL filtering.

Expected Mumble behavior:

- `Messages.cpp:1674-1676`: check `TextMessage` on each direct channel target.
- `Messages.cpp:1705-1707`: check `TextMessage` on each tree root.
- `Messages.cpp:1720`: only include descendants where sender has `TextMessage`.
- `Messages.cpp:1743-1745`: check `TextMessage` on each direct target user's current channel.

Recommended fix:

- For each `channel_id`, require sender `TextMessage` on that channel.
- For each `tree_id`, require sender `TextMessage` on the tree root; while walking descendants, include only channels where sender has `TextMessage`.
- For direct session targets, require sender `TextMessage` on the target user's current channel.
- Preserve Mumble behavior of dropping/denying on invalid targets consistently.

### 3. Voice Target Routing Does Not Enforce `Whisper`

Local code:

- `src/client/handlers/voice_target.rs:37-45` stores requested sessions/channels without permission checks.
- `src/voice/routing.rs:435` resolves `AudioTarget::VoiceTarget`.
- `src/voice/routing.rs:314-318` sends direct session voice-target audio with `Whisper` context.
- `src/voice/routing.rs:323-365` sends channel/tree/link voice-target audio without checking sender `Whisper`.

Impact:

- A user can whisper/shout into channels or users where Mumble would require `Whisper`.

Expected Mumble behavior:

- `Server.cpp:2499`: check `Whisper` for simple channel targets.
- `Server.cpp:2536`: check `Whisper` for subtree/link target channels.
- `Server.cpp:2567`: check `Whisper` for direct session targets based on target user's current channel.

Recommended fix:

- Enforce `ACLPermissions::Whisper` during voice-target resolution before adding each recipient.
- Invalidate voice target caches on ACL changes, or resolve permission live as local code currently does.

### 4. `UserStats` Has No ACL Gate

Local code:

- `src/client/handlers/user_stats.rs:17-116` builds or fetches stats for target without `Ban`/`Enter` checks.
- Cross-node path dispatches and forwards owner payload without origin-side ACL validation.

Impact:

- Any authenticated user can query stats for any local or remote user.
- Depending on `build_user_stats_payload`, this can reveal certificates, IP address, bandwidth, idle time, and client metadata.

Expected Mumble behavior:

- `Messages.cpp:2340`: full/extended stats allowed for self or root `Ban`.
- `Messages.cpp:2342-2344`: otherwise require `Enter` on target user's current channel.
- Non-extended callers get less detail.

Recommended fix:

- If target is self: allow.
- Else if sender has root `Ban`: allow full details.
- Else require sender `Enter` on target current channel and restrict details.
- For cross-node targets, validate against replicated target channel state before dispatch, or include enough signed/validated context so the owner can enforce consistently.

### 5. Cross-Owner `UserState` Moderation Bypasses ACLs

Local code:

- `src/client/handlers/user_state.rs:42-75` dispatches cross-owner moderation before local ACL checks.
- `src/s2s/mod.rs:516-590` applies `UserStatePatch` without checking actor permissions.

Impact:

- For remote targets, moves, mute/deaf/suppress, priority speaker, and listener changes can bypass `Move`, `MuteDeafen`, `Enter`, and `Listen`.
- The comment says owner applies permissions, but current owner path only checks `expected_from_channel`.

Expected Mumble behavior:

- `Messages.cpp:805-812`: moving another user requires `Move` on source, and either actor `Move` on destination or target `Enter`.
- `Messages.cpp:830-832`: listener add requires target `Listen`.
- `Messages.cpp:865-867`: mute/deaf/priority speaker require `MuteDeafen`; client `suppress` is denied.

Recommended fix:

- Perform origin-side ACL checks before dispatch using replicated target state, or make owner look up actor state and enforce the same logic.
- Include `expected_from_channel` for all moderation patches that depend on target location.
- Do not allow cross-owner apply path to mutate channel-dependent state without ACL validation.

## High Findings

### 6. `QueryUsers` Leaks Registered User Lookup

Local code:

- `src/client/handlers/query_users.rs:31-51` queries authenticator users without ACL checks.

Impact:

- Any authenticated user can map user IDs and names.

Expected Mumble behavior:

- `Messages.cpp:2049-2059`: caller needs `Write` on at least one channel.

Recommended fix:

- Scan channels and require `Write` on at least one, then answer.
- Return silently or send permission denied consistently with Mumble.

### 7. `UserList` Is a No-Op Instead of Root `Register` Protected

Local code:

- `src/client/handlers/user_list.rs:7-25` logs and returns `Ok(())`.

Impact:

- Query/update behavior is missing. This is not an over-permission by itself, but it is wrong compared to Mumble and will break admin clients.

Expected Mumble behavior:

- `Messages.cpp:2197-2201`: root `Register` required.
- Empty list means query registered users; non-empty list updates/unregisters/renames users.

Recommended fix:

- Implement query/update or explicitly document unsupported behavior.
- Gate both query and update on root `Register`.

### 8. Temporary Channel Checks Use the Wrong Permission

Local code:

- `src/client/handlers/channel_state.rs:57-65` always checks `MakeChannel`.
- `src/client/handlers/channel_state.rs:70` reads `temporary`, but does not switch required permission.
- `src/client/handlers/channel_state.rs:202-211` moving/reparenting also checks `MakeChannel` only.

Impact:

- Users with permanent-channel creation rights but not temporary-channel rights can create or move temporary channels.

Expected Mumble behavior:

- `Messages.cpp:1376-1378`: creation uses `MakeTempChannel` when `temporary = true`.
- `Messages.cpp:1483-1486`: moving a temporary channel requires `MakeTempChannel` on new parent.

Recommended fix:

- Map local `ACLPermissions::TempChannel` to Mumble `MakeTempChannel`.
- On create: require `TempChannel` if `msg.temporary == true`, else `MakeChannel`.
- On reparent: use the moved channel's temporary state to choose the parent permission.

### 9. `ChannelState` `max_users` Update Has No `Write` Check

Local code:

- `src/client/handlers/channel_state.rs:266` applies `max_users` via patch.
- Existing `Write` checks cover name, description, position, and parent move, but not `max_users`.

Impact:

- Any authenticated user can change channel user limit if they send only `max_users`.

Expected Mumble behavior:

- `Messages.cpp:1533-1536`: `max_users` requires `Write`.

Recommended fix:

- Add `if msg.max_users.is_some() && !has_write { deny Write }`.

### 10. `UserState` Allows Incorrect Moderator Fields

Local code:

- `src/client/handlers/user_state.rs:213-236`: `priority_speaker` is grouped with moderator actions only for non-self targets.
- `src/client/handlers/user_state.rs:504-506`: self can set `priority_speaker`.
- `src/client/handlers/user_state.rs:217` accepts client-provided `suppress` in moderator action logic.

Impact:

- Users can mark themselves priority speaker.
- Clients can request `suppress` changes in ways Mumble rejects.

Expected Mumble behavior:

- `Messages.cpp:860-867`: mute/deaf/suppress/priority speaker are moderator fields; `suppress` from client is denied.

Recommended fix:

- Treat `priority_speaker` as moderator-only even for self unless Mumble intentionally differs.
- Reject incoming `suppress` updates from clients, or only allow internal server-side suppression changes.

### 11. Non-Self Comment/Texture Reset Uses Wrong Permission

Local code:

- `src/client/handlers/user_state.rs:274-282`: non-self comment update checks root `Move`.
- `src/client/handlers/user_state.rs:371-430`: texture handling does not apply a non-self `ResetUserContent` check.

Impact:

- Users with root `Move` can clear others' comments.
- Non-self texture behavior is blocked earlier by self-only field rejection, but it is not aligned with Mumble's specific root `ResetUserContent` permission.

Expected Mumble behavior:

- `Messages.cpp:895-897`: non-self comment reset requires root `ResetUserContent`.
- `Messages.cpp:921-923`: non-self texture reset requires root `ResetUserContent`.
- Non-self non-empty comment/texture is denied.

Recommended fix:

- Replace root `Move` with root `ResetUserContent` for non-self comment clearing.
- Decide whether to support non-self texture clearing; if supported, gate with root `ResetUserContent`.

### 12. `Authenticate` Does Not Check `Enter` on Default Channel

Local code:

- `src/client/handlers/authenticate.rs:243-252` checks root `Traverse`.
- `src/client/handlers/authenticate.rs:286-300` places user in default channel or root without checking `Enter` on that channel.

Impact:

- User can start in a default channel they cannot enter according to ACLs.

Expected Mumble behavior:

- During login, Mumble chooses/restores a channel and checks `Enter`; if not allowed it falls back.

Recommended fix:

- Before setting `current_channel_id`, compute permissions for candidate default channel.
- If missing `Enter`, fall back to root or another allowed channel.
- Set initial `suppress` from `Speak` on the selected channel.

### 13. `ContextAction` Missing Authenticated Guard

Local code:

- `src/client/handlers/context_action.rs:24-62` dispatches without `sender.is_authenticated()`.

Impact:

- Pre-auth clients can invoke registered context actions, depending on dispatcher reachability.

Expected Mumble behavior:

- `Messages.cpp:2140-2143`: context action uses authenticated setup.

Recommended fix:

- Add the same authenticated guard used by most other handlers.

## Medium Findings

### 14. `ACL` Handler Missing Root `Write` Override and Group Handling

Local code:

- `src/client/handlers/acl.rs:46-56` requires `Write` only on target channel.
- `src/client/handlers/acl.rs:102` returns `groups: Vec::new()`.
- Update path reads `msg.acls` but ignores `msg.groups`.

Impact:

- Root admins can be locked out if target channel denies propagated `Write`.
- Mumble ACL group management is absent from the handler.

Expected Mumble behavior:

- `Messages.cpp:1833-1843`: target `Write` OR root `Write` can edit ACLs.
- Query and update include ACL groups.

Recommended fix:

- Permit ACL edit when sender has either target `Write` or root `Write`.
- Implement channel groups or explicitly reject unsupported group updates.
- Return inherited/local groups in ACL query.

### 15. `UserRemove` Kick Permission Is Too Narrow

Local code:

- `src/client/handlers/user_remove.rs:36-48`: non-ban removal requires only `Kick`.

Impact:

- A user with `Ban` but not `Kick` cannot kick, while Mumble allows either `Ban` or `Kick` for non-ban removal.

Expected Mumble behavior:

- `Messages.cpp:1242-1245`: ban requires `Ban`; kick accepts `Ban | Kick`.

Recommended fix:

- For `ban = false`, allow if root permissions contain either `Kick` or `Ban`.
- Add explicit SuperUser target protection if SuperUser sessions are represented.

### 16. Channel Creation and Move Under Temporary Parents Not Denied

Local code:

- `src/client/handlers/channel_state.rs` validates parent existence and permissions, but does not reject temporary parents.

Impact:

- Users can create/move channels under temporary channels in cases Mumble rejects.

Expected Mumble behavior:

- `Messages.cpp:1387-1389`: cannot create under temporary parent.
- `Messages.cpp:1473-1475`: cannot move into temporary parent.

Recommended fix:

- Reject create/reparent if the parent channel is temporary.

### 17. `VoiceTarget` Setup Does Not Filter Invalid Targets

Local code:

- `src/client/handlers/voice_target.rs:37-45` stores session IDs and channel IDs without checking whether they exist.

Impact:

- Mostly correctness/performance: invalid targets persist until routing.

Expected Mumble behavior:

- `Messages.cpp:2288-2306` stores only existing sessions/channels.

Recommended fix:

- Resolve and store only existing local/known sessions and channels.
- Still enforce `Whisper` at routing time because permissions can change.

### 18. `UserState` Temporary Access Tokens and Listener Volume Adjustments Are Ignored

Local code:

- `src/messages/encoder/user_state.rs:53-56` models `temporary_access_tokens` and `listening_volume_adjustment`.
- `src/client/handlers/user_state.rs` does not apply temporary access tokens or listener volume adjustment.

Impact:

- ACLs based on temporary access tokens will not work as Mumble clients expect.
- Listener volume changes are ignored.

Expected Mumble behavior:

- `Messages.cpp:793-798`: temporary access tokens are used during the user state operation.
- `Messages.cpp:1105-1116`: listener volume adjustment is applied.

Recommended fix:

- Implement temporary token scoping for the duration of the operation.
- Apply listener volume adjustments or reject unsupported fields explicitly.

## Findings That Are Mostly Correct

### `BanList`

Local code:

- `src/client/handlers/ban_list.rs:30-36` requires root `Ban`.

Expected Mumble behavior:

- `Messages.cpp:667-668` requires root `Ban`.

Status:

- Check is present, subject to evaluator correctness.

### `ChannelRemove`

Local code:

- `src/client/handlers/channel_remove.rs:46-52` requires `Write`.
- Root channel deletion is rejected.

Expected Mumble behavior:

- `Messages.cpp:1595-1597` requires `Write` and non-root.

Status:

- Check is present, subject to evaluator correctness.

### `RequestBlob`

Local code:

- `src/client/handlers/request_blob.rs` serves session textures/comments and channel descriptions without ACL checks.

Expected Mumble behavior:

- `Messages.cpp:2449-2492` also has no ACL gate.

Status:

- Close to upstream. Permission info attached to returned channel state still depends on the evaluator.

### `PluginDataTransmission`

Local code:

- `src/client/handlers/plugin_data_transmission.rs` has no ACL gate.

Expected Mumble behavior:

- `Messages.cpp:2501-2559` has no ACL gate.

Status:

- ACL-wise acceptable. Separate issues: local code lacks Mumble's data/data_id size validation and rate limit.

## Recommended Fix Order

1. Fix `src/acl.rs` effective permission evaluation first.
2. Fix hard bypasses:
   - `PermissionQuery`
   - `TextMessage`
   - voice target `Whisper`
   - `UserStats`
   - cross-owner moderation ACL validation
3. Fix high-impact handler mismatches:
   - `ChannelState` `TempChannel` and `max_users`
   - `UserState` moderator fields and `ResetUserContent`
   - `QueryUsers` and `UserList`
   - default-channel `Enter` during authenticate
4. Add integration tests for each permission:
   - Denied `TextMessage`
   - Denied `Whisper`
   - Denied `UserStats` for hidden channel
   - `MakeChannel` allowed but `TempChannel` denied
   - `max_users` without `Write`
   - cross-node move/mute/listen denial
   - `PermissionQuery` returns real bits

