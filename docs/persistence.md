# Persistence

[Docs index](README.md)

`blob_storage_dir` controls server-side durable state. The development config uses:

```toml
blob_storage_dir = "state"
```

When `blob_storage_dir` is omitted, persistence-backed components run in memory where supported.

## Stored Data

The persistence directory stores:

- Channel snapshots and write-ahead logs.
- Client state logs used for replay and server-to-server propagation.
- Channel blobs and session blob cache data.
- `user_channel_cache.db` for TTL-bound last/listening channel restoration. Legacy `user_channel_cache.json` data is imported on first startup after upgrade.
- WASM authenticator durable `state_*` data under `wasm_authenticator`.
- S2S transport adaptive compression dictionary cache and strict-replication terminal journals when `s2s.persistence_dir` points at persistent storage.

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
persistence_dir = "state/s2s"
```

Strict replication uses one cumulative capability version, currently `2`.
The local LSA starts at version `0`; it promotes automatically only after all
of these conditions hold:

- `s2s.persistence_dir` passes the durable-state probe and boot-epoch check.
- The production S2S manager has declared and successfully registered its
  complete expected strict-topic set (Channel and Ban, plus the pre-release
  workload when enabled), and every runtime reports support for version `2`.
  Valid lazy channel scopes are probed when they register as well.
- The local S2S identity can construct a bounded, authenticated v2
  origin-proof envelope.
- The local routed payload budget is at least 48 KiB, and every required
  minimal authenticated v2 control frame for every registered strict topic
  fits `strict_max_catchup_bytes`, the transport payload budget, and that
  48 KiB protocol ceiling.

Therefore a writable `s2s.persistence_dir` by itself does not enable strict
v2 when server repositories are in memory (`blob_storage_dir` is omitted).
There is no capability setting to flip manually. Normal shared-S2S storage
probe recovery re-promotes an already registered node automatically when no
repository capability loss is latched. A terminal-journal failure is
process-sticky until repair and restart. An active repository losing its v2
durability contract immediately withdraws the LSA to version `0` and remains
fail-closed until a coordinated repository re-registration (normally during
restart).

Older strict wire payloads remain recognizable during coordinated upgrades,
but recognition is not protocol participation: an unauthenticated strict
payload is discarded before it can change runtime state or trigger a reply.
Current nodes originate only authenticated v2 strict frames.

V2 strict snapshot catchup is resumable. `strict_max_catchup_bytes` limits
each authenticated replication frame, while
`strict_max_snapshot_transfer_bytes` limits the complete snapshot retained by
one strict-topic runtime across all source-pinned images and partial receiver
assemblies (default: 64 MiB). The source pins one image per peer for the
transfer TTL and sends an explicit rejection when it cannot safely serve that
image under the aggregate limit; a receiver that cannot append a chunk drops
its partial image and returns to the throttled history-election retry path.
Size the aggregate limit for concurrent transfers as well as the largest
durable Channel or Ban snapshot in the deployment. This is a
resource-protection limit, not a strict-protocol capability setting.

At startup, strict replication also checks every persisted terminal decision
against the effective authenticated catchup-frame budget (the lower of
`strict_max_catchup_bytes`, the transport payload limit, and the fixed 48 KiB
v2 ceiling). If one decision cannot fit, the node retains and replays it
locally but permanently advertises strict capability version `0` for that
process. Raise the configurable frame budget where possible, or
migrate/compact the affected terminal journal, then restart the node. This
prevents the node from advertising a version whose durable fences cannot be
replicated to a peer.

## Backup Guidance

Back up these items together for a production node:

- `config.toml`
- TLS private keys and certificates
- authenticator code/modules and their secrets
- `blob_storage_dir`
- `s2s.persistence_dir` when clustering is enabled

Stop the service or take a filesystem-consistent snapshot when possible.
