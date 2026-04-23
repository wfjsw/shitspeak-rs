# Channel Repository Issues

## Root cause of "channels not appearing after reconnect/restart"
- `ChannelRepository::new_in_memory()` created an empty `channels` map without a root channel (id=0).
- `open()` correctly inserts root if missing, but `new_in_memory()` did not.
- The auth handler's BFS channel tree broadcast starts at `queue.push_back(0u32)`, looks up `ch_map.get(&0)`, finds nothing, and silently skips — sending zero ChannelState messages.
- **Fix**: Added root channel creation to `new_in_memory()`.

## Secondary issue: in-memory log not populated on restart
- `open()` replays WAL entries into the channels map but does NOT populate the in-memory `log` VecDeque.
- This means `get_log_since()` returns empty after restart, causing `replay_channel_log_gap` to fail for reconnecting clients with non-zero `last_channel_version`.
- Mitigated by the fact that reconnecting clients get a full channel tree during auth and their `last_channel_version` is reset.
- If full WAL replay support is needed, the log should be populated from WAL entries during `open()`.
