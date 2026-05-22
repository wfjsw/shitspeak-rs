# ACL spec audit against original Mumble

Compared local ACL implementation to original Mumble/Murmur behavior and docs.

Reference points:
- Original Mumble ACL effectivePermissions starts with default Traverse|Enter|Speak|Whisper|TextMessage|Listen, walks channels root-to-target, applies ACL entries in channel/list order by ORing allow then clearing deny, tracks Traverse/Write separately, resets to defaults when an evaluated channel has inherit disabled, grants Write-implied permissions after evaluation, and gives superuser All except Speak|Whisper. Source: Fossies Mumble src/ACL.cpp lines ~103-199.
- Original group system is per-channel with inherit/inheritable/add/remove/members, plus temporary memberships; getACL/setACL include both ACLList and GroupList. Official Mumble Slice docs: Murmur::Group and Murmur::Server getACL/setACL.

Local issues observed:
- src/acl.rs evaluate_permission walks target-to-root and unions all allow/deny bits, then returns allowed & !denied. This makes deny globally sticky and prevents child/later allow from overriding parent/earlier deny, unlike original Mumble's ordered overwrite semantics.
- Write does not imply Traverse/Enter/MuteDeafen/Move/MakeChannel/LinkChannel/TextMessage/TempChannel/Listen or root admin bits; local checks often look for each bit directly. Original Write implies all except Speak/Whisper.
- Traverse is not enforced as a path gate. Original returns no permissions if user cannot traverse and does not have Write while walking ancestors.
- Superuser returns BitFlags::all locally, but original superuser excludes Speak and Whisper.
- Channel/root admin bits Kick/Ban/Register/SelfRegister/ResetUserContent are represented but not restricted to root-channel effective evaluation. Original only grants root-only bits on root channel.
- Group persistence and per-channel group inheritance are missing. ACL handler ignores msg.groups and replies groups: Vec::new(); local membership uses authenticator/global client groups only.
- Group selector support is partial and nonstandard: supports all/none/auth/strong/in/out, ! and ~, tokens/cert/IP extensions; missing original sub/sub,... selector and real per-channel group membership semantics. Local in/out compares against numeric target/current channel ids instead of user's actual current channel.
- ACL query flattening returns ACLs but no inherited groups and likely target-to-root order.
- PermissionQuery handler computes permissions but returns hard-coded 0x1F0FFF instead of computed perms.
- TextMessage handler relays direct/channel/tree messages without checking ACLPermissions::TextMessage.
- Temporary channel creation checks MakeChannel, not TempChannel/MakeTempChannel, and creator is not automatically made admin of subchannel.
- Voice routing only enforces Speak for linked normal routing and suppress is only updated on channel moves; Whisper/target routing does not check sender Whisper permission.

Potentially okay/close:
- Permission bit numeric values mostly match Mumble/Murmur Slice constants through Listen plus extra ResetUserContent.
- apply_here/apply_subs and inherit_acl are represented.
- Move/LinkChannel checks are broadly aligned in places, though evaluator semantics can still make them wrong.
