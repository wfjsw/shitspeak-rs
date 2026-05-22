# Message handler ACL audit 2026-05-17

Compared shitspeak-rs client handlers against local D:/mumble Murmur sources:
- ACL semantics: D:/mumble/src/ACL.cpp lines 103-232
- Handler gates: D:/mumble/src/murmur/Messages.cpp and D:/mumble/src/murmur/Server.cpp

Critical/high issues:
- PermissionQuery computes permissions but returns hard-coded 0x1F0FFF in src/client/handlers/permission_query.rs:41-42.
- TextMessage relays direct/channel/tree messages without TextMessage permission checks in src/client/handlers/text_message.rs. Mumble checks TextMessage per channel/tree/direct target.
- Voice routing does not enforce sender Whisper for voice targets; normal Speak is only mirrored by suppress on moves and can go stale after ACL changes. Mumble checks Whisper per target and updates suppress after ACL changes.
- UserStats has no ACL checks for local or cross-node targets. Mumble allows full details only for self or root Ban and otherwise requires Enter on target's channel.
- Cross-owner UserState moderation dispatches before local permission checks and owner apply path does not revalidate ACLs. Remote target move/mute/deaf/suppress/listen can bypass Move/MuteDeafen/Listen/Enter.
- QueryUsers leaks registered users without Mumble's Write-on-any-channel gate.
- UserList is no-op; Mumble requires root Register and supports query/update.
- ChannelState: temporary channel creation/reparent uses MakeChannel instead of TempChannel/MakeTempChannel; max_users updates have no Write check; moving/creating under temporary parent is not denied.
- UserState: client can set own priority_speaker without MuteDeafen; suppress from clients is allowed if moderator has MuteDeafen but Mumble denies suppress from clients; non-self comment clearing uses Move instead of ResetUserContent; non-self listener add/remove not rejected; user_id registration ignored.
- Authenticate places user into default channel without checking Enter on that channel; only root Traverse is checked.
- ContextAction has no authenticated guard locally, unlike Mumble MSG_SETUP(Auth).

Medium issues:
- ACL handler allows only target-channel Write, missing Mumble root-Write override for ACL edits; ignores ACL groups; query ordering/group response non-spec.
- UserRemove kick requires Kick only; Mumble allows Ban OR Kick for non-ban remove. No explicit SuperUser-target protection.
- UserState temp-channel moderation parent check missing; temporary access tokens ignored.
- VoiceTarget accepts unresolved sessions/channels instead of filtering at setup.

Likely okay / not ACL gated in upstream:
- BanList root Ban gate present.
- ChannelRemove Write + non-root gate present, subject to broken evaluator.
- RequestBlob appears similar to Mumble: no ACL gate for requesting blobs.
- PluginData has no ACL gate in Mumble, though local lacks Mumble size/rate validation.
- Version/Ping/VoiceTarget/PermissionQuery use no-unidle/auth gates in Mumble; local auth gates mostly exist except ContextAction/CryptSetup.
