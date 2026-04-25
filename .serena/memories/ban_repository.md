# Ban Repository

## Types (src/ban_repository.rs)
- `BanEntry` — single ban: address, bits, mask, name, hash, reason, start, duration_secs
- `BanOp` enum — Add, Remove, Clear
- `BanOperation` — BanOp + BanEntry + timestamp
- `Snapshot` — serializable state snapshot
- `BanRepository` — main repository with WAL persistence

## Persistence
- WAL: append-only newline-delimited JSON (`bans.wal.jsonl`)
- Snapshot: `bans.snapshot.json`
- Startup: load snapshot → replay WAL
- `apply_op_to_list` helper function

## Features
- Ban by IP address (with CIDR mask)
- Ban by certificate hash
- Ban by username (exact match)
- Temporary bans with duration
- Ban list query support
