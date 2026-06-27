# Persistence

[Docs index](README.md)

`blob_storage_dir` controls server-side durable state. The development config uses:

```toml
blob_storage_dir = "data"
```

When `blob_storage_dir` is omitted, persistence-backed components run in memory where supported.

## Stored Data

The persistence directory stores:

- Channel snapshots and write-ahead logs.
- Client state logs used for replay and server-to-server propagation.
- Channel blobs and session blob cache data.
- `user_channel_cache.json` for TTL-bound last/listening channel restoration.
- WASM authenticator durable `state_*` data under `wasm_authenticator`.
- S2S transport adaptive compression dictionary cache when `s2s.persistence_dir` points at persistent storage.

For durable deployments, back up the application state directory and place it on storage that survives process and host restarts.

## Tuning

Common persistence knobs:

```toml
channel_log_max_entries = 10000
client_log_max_entries = 10000
channel_snapshot_every_ops = 10
channel_snapshot_every_secs = 60
channel_wal_compaction_expire_count = 2000
```

S2S state has its own root:

```toml
[s2s]
persistence_dir = "s2s-state"
```

## Backup Guidance

Back up these items together for a production node:

- `config.toml`
- TLS private keys and certificates
- authenticator code/modules and their secrets
- `blob_storage_dir`
- `s2s.persistence_dir` when clustering is enabled

Stop the service or take a filesystem-consistent snapshot when possible.
