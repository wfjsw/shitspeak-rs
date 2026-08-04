# Configuration

[Docs index](README.md)

ShitSpeak reads `config.toml` from the current working directory. The checked-in `config.toml` is a local-development reference with comments for most available settings.

This page explains how the file is loaded, what the major settings do, and gives copyable examples for common deployment shapes.

## Loading Rules

The server loads:

1. `config.toml` from the process working directory.
2. Environment variable overrides with the `SHITSPEAK_` prefix.

Use a double underscore between TOML table levels and retain single
underscores inside key names:

```powershell
$env:SHITSPEAK_LISTEN = "0.0.0.0:64738"
$env:SHITSPEAK_MAX_USERS = "250"
$env:SHITSPEAK_AUTHENTICATOR__BACKEND = "wasm"
$env:SHITSPEAK_AUTHENTICATOR__WASM__PATH = "auth/auth.wasm"
$env:SHITSPEAK_PRIVACY__CERTIFICATE_HASH_SECRET = "replace-with-a-long-random-secret"
```

TOML remains the clearest format for arrays and tables. Environment variables are best for simple scalar values and secrets.

The older single-underscore nesting form remains accepted for compatibility,
but it is ambiguous when a key itself contains underscores. Prefer the
double-underscore form above. Unknown keys are ignored, so review spelling and
nesting carefully when an override appears to have no effect.

## Minimal Local Config

These are the required top-level fields plus a small practical baseline:

```toml
listen = "0.0.0.0:64738"
register_name = "ShitSpeak Local"

cert_path = "tls/server-cert.pem"
key_path = "tls/server-key.pem"

send_version = true
send_build_info = true
send_os_info = true

allowed_proxies = []
min_client_version = 0
max_users = 100

welcome_text = "Welcome to ShitSpeak"
root_channel_name = "Root"
default_channel = 0

blob_storage_dir = "state"

[authenticator]
backend = "demo"
```

Provide a TLS certificate and key at the configured paths before starting the
server.

## Production-Style Single Node

This example keeps the shape small while showing the settings that usually matter first:

```toml
listen = "0.0.0.0:64738"
register_name = "Example Voice"

cert_path = "/etc/shitspeak-rs/tls/server-cert.pem"
key_path = "/etc/shitspeak-rs/tls/server-key.pem"

send_version = true
send_build_info = false
send_os_info = false

allowed_proxies = ["10.0.0.10/32"]
min_client_version = 0
max_users = 250

welcome_text = "Welcome"
max_bandwidth = 72000
allow_html = true
max_text_message_length = 5000
max_image_message_length = 131072

root_channel_name = "Lobby"
default_channel = 0
cert_required = true

udp_voice_enabled = true
udp_ping_enabled = true
udp_ping_user_count_scope = "local"
udp_channel_size = 4096

client_idle_timeout_secs = 30
authenticate_timeout_ms = 30000
# Set to 0 to disable the login queue and concurrency limit.
# Default when omitted: floor(3rd root(active CPU count)), minimum 1.
# auth_finalization_concurrency = 1
pending_delete_timeout_ms = 5000

blob_storage_dir = "/var/lib/shitspeak-rs"

required_groups = ["member"]
send_permission_info = true
hide_users_without_traverse = true
hide_channels_without_traverse = true
show_node_id_for_superusers = true

[authenticator]
backend = "wasm"

[authenticator.wasm]
path = "/etc/shitspeak-rs/auth/auth.wasm"

[privacy]
protect_certificate_hashes = "irreversible"
certificate_hash_secret = "replace-with-a-long-random-cluster-secret"
# Prefer SHITSPEAK_PRIVACY__CERTIFICATE_HASH_SECRET for real deployments.

[acl]
debug_acl_enter = false
explicit_enter_deny_overrides_write = true
preserve_write_acl_on_edit = false
grant_temp_channel_creator_acl = true
reevaluate_speak_on_acl_change = true
allow_move_without_traverse = false
```

## Top-Level Server Settings

### Listener And TLS

```toml
listen = "0.0.0.0:64738"
cert_path = "tls/server-cert.pem"
key_path = "tls/server-key.pem"
```

`listen` is the default client TCP and UDP address. The server binds TCP and UDP on the same socket address. If the port is `0`, the server chooses an available dynamic port pair.

`cert_path` and `key_path` are the TLS identity used for Mumble client connections. New handshakes can pick up changed certificate/key files through hot reload.

### Public Registration

Public Mumble server-list registration activates only when the required fields are complete:

```toml
register_name = "Example Voice"
register_password = "registry-password"
register_url = "mumble://voice.example.com:64738"
register_hostname = "voice.example.com"
register_location = "Dallas, USA"
```

Keep `udp_ping_enabled = true` for normal public-list behavior.

### Version Disclosure

```toml
send_version = true
send_build_info = false
send_os_info = false
```

These control how much server version/build/platform information is advertised to clients.

### Client Limits

```toml
min_client_version = 0
max_users = 100
max_bandwidth = 72000
max_text_message_length = 5000
max_image_message_length = 131072
```

`max_bandwidth` is the default per-client bandwidth value advertised to clients. Authenticators can override it per user by returning `max_bandwidth`.

### Channel Defaults

```toml
welcome_text = "Welcome to ShitSpeak"
allow_html = true
root_channel_name = "Root"
default_channel = 0
```

`default_channel` is the channel id used for new sessions when no persisted last/listening channel restoration applies.

`cert_required = true` rejects native clients that do not present a TLS client
certificate. It checks certificate presence, not whether the certificate chains
to a trusted client CA.

## PROXY Protocol

Configure trusted upstream proxies with `allowed_proxies`:

```toml
allowed_proxies = [
  "127.0.0.1/32",
  "10.0.0.0/24",
]
```

Only list addresses that are allowed to send PROXY protocol connection metadata. Do not include broad untrusted networks.

## UDP

```toml
udp_voice_enabled = true
udp_ping_enabled = true
udp_ping_user_count_scope = "cluster" # cluster, local
udp_channel_size = 2048
```

`udp_voice_enabled = false` keeps the UDP loop available for ping behavior but drops UDP voice packets.

`udp_ping_user_count_scope` controls whether UDP ping responses report clusterwide users/max users or only users/max users on this node.

## Voice

The `[voice]` table controls when delayed voice work is discarded and how long
Linux UDP batch sends may wait through transient socket backpressure. These
settings are latency and load-shedding controls; they do not resize queues or
act as a jitter buffer.

```toml
[voice]
max_udp_packet_age_ms = 250
max_routing_queue_age_ms = 250
udp_send_retry_budget_ms = 2
```

| Setting | Default | Meaning |
| --- | ---: | --- |
| `max_udp_packet_age_ms` | `250` ms | Maximum time a native UDP packet may wait in the UDP processing queue before decode and decrypt. Older packets are dropped at the `udp_packet` stage. |
| `max_routing_queue_age_ms` | `250` ms | Maximum accepted age for decoded audio in the per-sender routing queue and the local-fanout queue. The local-fanout check uses accumulated routing, resolution, and fanout-queue age. |
| `udp_send_retry_budget_ms` | `2` ms | On Linux, maximum elapsed time a UDP `sendmmsg` batch may spend retrying `WouldBlock`. `0` fails fast. This setting is ignored by the non-Linux per-datagram send path. |

The age limits are checked when workers dequeue an item. Increasing a limit
can reduce stale-drop counts during short stalls, but it permits older audio to
continue through the pipeline and makes workers spend time on a backlog instead
of newer packets. Decreasing a limit sheds load sooner at the cost of more
audible gaps. A value of `0` effectively rejects work that experiences any
measurable queue delay.

`max_routing_queue_age_ms` is shared by two stages. A packet can pass the
routing-queue check and still be discarded later if recipient resolution plus
local-fanout waiting pushes its accumulated age over the same limit. Queue
capacity can therefore remain available while stale drops occur.

`max_udp_packet_age_ms` applies only to native UDP ingress, not TCP-tunneled
voice. `max_routing_queue_age_ms` applies to decoded local-client voice from
either ingress transport; S2S frames use their separate S2S voice pipeline.

Increasing `udp_send_retry_budget_ms` can ride through brief socket send
pressure, but the affected voice flush waits for the retry and can add pressure
to upstream queues. Keep it small relative to both age limits.

The three `[voice]` values above are read from the hot-reloaded configuration.
Changes under `[voice.dispatch]` require a restart because the dispatch plan is
resolved once during startup.

Use `shitspeak_voice_stale_drops_total{stage="udp_packet"}` and
`shitspeak_voice_stale_drops_total{stage=~"routing_queue|local_fanout_queue"}`
to observe the age limits. UDP retry exhaustion is reported by
`shitspeak_voice_udp_send_events_total{result="retry_budget_exhausted"}`.

### Dispatch Calibration

The server calibrates UDP voice encryption fan-out before it starts accepting
connections. It chooses independent Rayon thresholds and recipient-run sizes
for payloads up to and including 512 bytes and payloads above 512 bytes.

```toml
[voice.dispatch]
mode = "startup_calibrated" # startup_calibrated, sequential, fixed

# Used only when mode = "fixed".
small_payload_rayon_threshold = 512
small_payload_rayon_min_len = 256
large_payload_rayon_threshold = 512
large_payload_rayon_min_len = 256
```

`startup_calibrated` benchmarks sequential and Rayon encryption at startup and
selects both profiles. If Rayon has fewer than two workers, the server selects
sequential dispatch; if calibration fails, it logs a warning and uses a
conservative fallback.

`sequential` disables Rayon voice fan-out. `fixed` is an operational override
for controlled experiments or recovery. In fixed mode, each
`*_rayon_threshold` is the recipient count at which Rayon dispatch begins, and
each `*_rayon_min_len` is the target recipient-run size for parallel work, not
a per-packet task. Runs are balanced, so their actual size can be smaller than
the target when that permits useful parallelism. Dispatch creates no more runs
than there are Rayon workers. All four values must be at least `1`, and a
target run length cannot exceed its corresponding threshold. The four numeric
settings are ignored outside fixed mode.

## Timeouts

```toml
client_idle_timeout_secs = 30
authenticate_timeout_ms = 30000
# Set to 0 to disable the login queue and concurrency limit.
# Default when omitted: floor(3rd root(active CPU count)), minimum 1.
# auth_finalization_concurrency = 1
pending_delete_timeout_ms = 5000
```

`authenticate_timeout_ms` starts after TLS setup. Positive `auth_finalization_concurrency` values limit how many clients can concurrently create UDP crypt setup state, run authenticator backend work, and perform the initial sync/publish path. Authenticator calls run on a bounded background-priority runtime (nice `+10` on Linux, lowest thread priority on Windows); bulk ACL refresh evaluation uses a separate one-worker runtime with the same background priority, while ordinary ACL checks remain on their existing path. Setting `auth_finalization_concurrency` to `0` bypasses the login queue and admission limit. When omitted, it defaults to `floor(3rd root(active CPU count))` with a minimum of 1. `pending_delete_timeout_ms` controls rollback timing for pending two-phase channel deletes.

Client projection delivery uses a bounded outbound writer queue. A client that
cannot drain that queue is disconnected when the queue fills so it cannot
block other clients assigned to the same projection shard.

## Persistence

```toml
blob_storage_dir = "state"
user_channel_cache_record_remote_sessions = false
channel_log_max_entries = 10000
client_log_max_entries = 10000
channel_snapshot_every_ops = 10
channel_snapshot_every_secs = 60
channel_wal_compaction_expire_count = 2000
```

`client_log_max_entries` bounds the replay history retained in memory for each
client-state origin and defaults to `2000` when omitted. It is read when the
client repository is created, so a hot-reload change takes effect only after
restart. A shorter history saves memory but makes a lagging projection rebase
from the materialized client snapshot more often. The client-state log is not
written under `blob_storage_dir` and is rebuilt from live and S2S activity
after every process start.

`blob_storage_dir` stores channel snapshots, write-ahead logs, channel blobs,
session blob cache data, user channel cache data, and WASM authenticator
durable state.

`user_channel_cache_record_remote_sessions` controls whether
`user_channel_cache.db` also records current/listening channel state for
sessions hosted on remote S2S nodes. It defaults to `false`, so the database
only records sessions logged in to this server. Enable it when each node should
retain remote session channel state as well.

See [Persistence](persistence.md) for backup guidance.

## Authentication

Select the backend under `[authenticator]`:

```toml
[authenticator]
backend = "demo" # demo, wasm, exec
```

### Demo Authenticator

```toml
[authenticator]
backend = "demo"
```

Use this only for local development.

### WASM Authenticator

```toml
[authenticator]
backend = "wasm"

[authenticator.wasm]
path = "auth/auth.wasm"
file_access_dir = ["auth/files"]
working_dir = "auth/files"
```

The server keeps a reusable pool of WASM instances and creates more as queued authenticator work needs them. Positive `auth_finalization_concurrency` values control how many login authenticator calls can run at once and also throttle per-client UDP crypt setup. Setting it to `0` bypasses that queue and limit, although WASM instance creation itself remains serialized. `file_access_dir` bounds file access from the WASM raw stream imports. When it is empty, file stream imports are unavailable.

### Exec Authenticator

```toml
[authenticator]
backend = "exec"

[authenticator.exec]
mode = "exec_long_running" # exec_ephemeral, exec_long_running
long_running_request_mode = "serialized" # serialized, async
command = "auth-helper"
args = ["--config", "auth/config.toml"]
environment = { AUTH_ENDPOINT = "https://auth.example", AUTH_MODE = "production" }
working_dir = "auth"
timeout_ms = 30000
max_response_bytes = 16777216
# uid = 1001
# gid = 1001
```

Exec authenticators exchange JSON over stdin/stdout. `environment` adds or overrides variables in the helper process environment; other variables are inherited from the server, and configured values are literal. `long_running_request_mode = "serialized"` keeps one request in flight at a time for compatibility. `async` allows multiple in-flight requests and requires each response to echo the request's `request_id`. See [Authentication](authentication.md) for request/response contracts and WASM imports.

## Access Control

### Required Groups

```toml
required_groups = ["member", "admin"]
```

If this list is empty, any authenticated user can connect. If it is non-empty, the authenticated user must belong to at least one listed group.

### Permission Visibility

```toml
send_permission_info = true
hide_users_without_traverse = true
hide_channels_without_traverse = true
show_node_id_for_superusers = true
```

`send_permission_info` includes per-client channel enter hints in `ChannelState` messages. `hide_users_without_traverse` hides users and listeners whose channels the viewer cannot traverse. `hide_channels_without_traverse` separately hides channels the viewer cannot traverse; enable both options to hide the channel and its users/listeners together. The server rejects `hide_channels_without_traverse = true` unless `hide_users_without_traverse = true`. Visibility is reevaluated for affected channels and online users when ACLs or the viewer's user, group, token, or superuser state changes. `show_node_id_for_superusers` appends a compact node marker such as `[n2]` to display names in `UserState` messages sent to superusers.

### ACL Behavior Toggles

```toml
[acl]
debug_acl_enter = false
explicit_enter_deny_overrides_write = true
preserve_write_acl_on_edit = false
grant_temp_channel_creator_acl = true
reevaluate_speak_on_acl_change = true
allow_move_without_traverse = false
```

- `debug_acl_enter`: when true, superusers ignore channel Enter denies.
- `explicit_enter_deny_overrides_write`: when true, explicit Enter denies remain denied even if Write would otherwise imply Enter.
- `preserve_write_acl_on_edit`: when true, registered non-superuser ACL editors keep a personal Write fallback if their edit would remove their own Write permission.
- `grant_temp_channel_creator_acl`: when true, temporary channel creators receive local ACL grants for missing Write, Enter, and Speak permissions.
- `reevaluate_speak_on_acl_change`: when true, ACL edits reevaluate Speak for clients currently in the changed channel subtree and update their `UserState.suppress` state.
- `allow_move_without_traverse`: when true, a moderator with the required Move permissions may move another user into a channel the target cannot traverse. It does not change self-move authorization. Hidden destination ancestors are revealed to the moved client only while needed and revoked after departure. The default is false.

The checked-in development config sets stricter values than the code defaults for some ACL toggles.

## Privacy

Certificate-hash privacy changes how non-superuser clients see other users' `UserState.hash` values:

```toml
[privacy]
protect_certificate_hashes = "irreversible" # false, true, irreversible, reversible
certificate_hash_secret = "replace-with-a-long-random-cluster-secret"
```

Supported values:

- `false`, `"disabled"`, `"disable"`, `"off"`, or `"none"`: disabled.
- `true` or `"irreversible"`: stable one-way remap.
- `"reversible"`: stable AES-based remap that can be restored with the shared secret.

The viewer's own certificate hash is sent unchanged. In clusters, every node must use the same secret.

Prefer storing the secret in the environment:

```powershell
$env:SHITSPEAK_PRIVACY__CERTIFICATE_HASH_SECRET = "replace-with-a-long-random-cluster-secret"
```

## GeoIP

```toml
[geoip]
enabled = true
maxmind_database_path = "GeoLite2-City.mmdb"
cache_ttl_secs = 86400
cache_capacity = 4096
```

This is used for shared GeoIP resolution such as ACL IP masks. S2S topology observability can use manual `[s2s.geo]` coordinates or egress probing separately.

Disable GeoIP when no database is available:

```toml
[geoip]
enabled = false
```

## Virtual Entrypoints

`[[server_entrypoints]]` can add per-tenant listener ports and SNI mappings:

```toml
[[server_entrypoints]]
server_id = "tenant-a"
listen = "0.0.0.0:64748"
udp_ping_status_server_id = "tenant-a"
sni = ["tenant-a.example.com", "voice-a.example.com"]

[[server_entrypoints]]
server_id = "tenant-b"
sni = ["tenant-b.example.com"]
```

If `listen` is omitted, the entrypoint only contributes SNI routing. An authenticator can also return `virtual_server_id` to route a user into a virtual server.

Ports must not collide with the default listener or with each other.

## Server-To-Server

S2S is explicit opt-in. Disabled configs do not need S2S certificate or listener settings.

```toml
[s2s]
enabled = true
ca_path = "s2s/ca.pem"
cert_path = "s2s/node-1-cert.pem"
key_path = "s2s/node-1-key.pem"
persistence_dir = "state/s2s"

tcp_listen = "0.0.0.0:64739"
kcp_listen = "0.0.0.0:64740"
quic_listen = "0.0.0.0:64740"
udp_listen = "0.0.0.0:64740"

tcp_advertise = "node-1.example.com:64739"
kcp_advertise = "node-1.example.com:64740"
quic_advertise = "node-1.example.com:64740"
udp_advertise = "node-1.example.com:64740"

status_http_listen = "0.0.0.0:64750"

seed_addresses = [
  { transport = "tcp", addr = "node-2.example.com:64739" },
  { transport = "quic", addr = "node-3.example.com:64741" },
]
```

KCP, QUIC, and packet-encrypted UDP may share one local UDP port. The server
binds one UDP socket and demultiplexes protocol frames in userspace using
`0x81` for KCP, `0x82` for QUIC, and `0x80` for UDP. Upgrade participating
nodes together because legacy unprefixed UDP-family traffic is rejected.

Listen fields accept a single socket address or an array:

```toml
[s2s]
tcp_listen = ["0.0.0.0:64739", "[::]:64739"]
```

Advertisement fields accept a single value or an array. Advertised addresses must not be unspecified addresses such as `0.0.0.0`.

Common LAN/VPN options:

```toml
[s2s]
advertise_private_ips = true
local_interface_advertise = ["tailscale0", "Tailscale"]
```

Manual dashboard coordinates:

```toml
[s2s.geo]
latitude = 32.7767
longitude = -96.7970
city = "Dallas"
region = "TX"
country = "US"
source = "manual"
```

Without `[s2s.geo]`, the server probes Cloudflare's check-perf endpoint for
the egress location. Failed probes retry with exponential backoff from one
second to a five-minute cap; the first valid result is used for the rest of
the process lifetime.

Transport and replication tuning examples:

```toml
[s2s.transport]
latency_ewma_alpha = 0.2
jitter_ewma_alpha = 0.0625
packet_loss_ewma_alpha = 0.02
ping_interval_secs = 2
idle_ping_interval_secs = 10
native_stats_interval_secs = 10
stream_write_timeout_ms = 1000
# Deadline for establishing and acknowledging all required QUIC v2 lanes.
quic_session_setup_timeout_ms = 10000
# QUIC unreliable DATAGRAM queue budgets. Zero disables that local direction,
# not the s2s/2 ALPN offer; keep both nonzero for normal v2 operation.
# Nonzero values must be at least 1200 bytes.
quic_datagram_send_buffer_bytes = 65536
quic_datagram_receive_buffer_bytes = 262144
max_pending_pings = 64
recent_probe_retry_cap_secs = 30
stale_probe_retry_cap_secs = 600
stale_probe_age_secs = 3600
unconfirmed_address_retry_floor_secs = 300
unconfirmed_address_retry_cap_secs = 1800
unconfirmed_address_decay_failures = 5
dial_attempt_timeout_secs = 10
self_seed_quarantine_secs = 3600
unselected_link_probe_interval_secs = 30
max_dial_attempts_per_peer_tick = 1
max_outgoing_connections = 1024
# UDP-family sampling and health gates. Unhealthy datagram candidates are
# excluded; streams remain the fallback when no viable datagram path exists.
udp_family_min_samples = 32
udp_family_probe_loss_block_count = 3
udp_family_block_loss_ppm = 250000
udp_family_loss_excess_over_tcp_ppm = 50000
# Observe separate BestEffort datagram states. Raw UDP uses weighted effective
# loss. QUIC DATAGRAM uses path-local enqueue rejection and writer-failure
# evidence; pressure, too-large, and ingress counters are diagnostic only.
# This is shadow-only and does not affect routing or KCP.
best_effort_datagram_effective_loss_suspect_ppm = 5000
best_effort_datagram_effective_loss_recover_ppm = 2500
best_effort_quic_datagram_health_suspect_ppm = 100000
best_effort_quic_datagram_health_recover_ppm = 10000
best_effort_datagram_suspect_bad_windows = 3
best_effort_datagram_recover_healthy_ms = 10000
large_rtt_threshold_ms = 100
lossy_link_threshold_ppm = 20000
bulk_payload_threshold_bytes = 65536
bulk_backlog_threshold_bytes = 262144
# Every BestEffort route prefers eligible raw UDP and fitting s2s/2 QUIC
# DATAGRAM paths over reliable streams. This percentage controls sticky
# challenger changes between otherwise comparable voice paths.
transport_switch_improvement_pct = 15
# Penalize KCP's measured cost for every BestEffort route while retaining it as
# the final fallback. Reliable traffic is unaffected.
best_effort_kcp_cost_penalty_pct = 25
# Soft voice-path stickiness prevents frame-by-frame path oscillation. An eligible
# datagram path may replace a reliable incumbent immediately; timing rules
# continue to govern other path changes.
voice_path_stickiness_enabled = true
voice_path_min_hold_ms = 750
voice_path_challenger_confirm_ms = 500
voice_path_idle_reset_ms = 2000
transport_metric_stale_after_ms = 1500
# Legacy queue capacity hints. Adaptive byte budgets use available memory;
# these only raise the per-lane minimum budget.
inbound_control_capacity = 16384
inbound_high_capacity = 32768
inbound_regular_capacity = 32768
outbound_capacity = 131072
compression_enabled = true
compression_min_bytes = 1024
compression_min_savings_percent = 10
compression_level = 1
compression_adaptive_dictionary_enabled = true
# Optional; all participating UDP peers must use identical dictionary bytes.
# compression_dictionary_path = "s2s-transport.zdict"

[s2s.transport.kcp]
nodelay = true
interval_ms = 10
fast_resend = 2
no_congestion = false
flush_write = true
flush_acks_input = true
failaway_with_alternative_ms = 250
failaway_without_alternative_ms = 750
no_progress_close_ms = 1500

[s2s.application.voice]
# "broadcast" is the default. "targeted" scopes voice fan-out by
# (server_id, channel_id) and requires fresh client replication state.
# A VoiceTarget for channel 0 with children enabled is treated as a
# whole-server shout: root permissions are checked once and recipients are
# filtered directly from server users. In targeted mode, whole-server and
# recursive targets fall back to broadcast until the recipient snapshot covers
# every current voice member.
delivery_strategy = "broadcast"
# Applies to both broadcast and targeted recipient sets. Enable only after
# every relay in the cluster understands distribution-tree forwarding.
# Broadcast uses the reserved group 0. Targeted traffic keeps a stable group
# for its server/channel target and changes its group version only when the
# resolved recipient-node set changes.
tree_delivery_enabled = true
reorder_max_delay_ms = 40
reorder_max_buffered_frames = 48
reorder_max_total_buffer = 4096
reorder_idle_reset_ms = 2000
reorder_disabled = false
adaptive_jitter_enabled = true
adaptive_jitter_min_delay_ms = 40
adaptive_jitter_max_delay_ms = 120
adaptive_jitter_growth_step_ms = 20
adaptive_jitter_decay_step_ms = 10
repair_enabled = true
transport_ttl_ms = 750
repair_transport_ttl_ms = 750
# Transport TTL for the NACK itself; defaults to repair_transport_ttl_ms. The
# payload separately carries the requester's remaining actionable gap time as
# a relative response deadline.
repair_request_ttl_ms = 750
repair_cache_ms = 1600
repair_loss_start_ppm = 10000
repair_full_dup_loss_ppm = 30000
repair_jitter_start_ms = 40
# At most two proactive copies may be requested per frame. The default is one.
# This caps demand; conserved-credit overflow is ranked separately by marginal
# on-time utility and destination fairness.
repair_max_extra_copies_per_frame = 1
# Percentages of the repair-credit cap. Unused reactive entitlement above the
# hard reserve is borrowable by proactive work. NACK and tail frames share a
# deadline-aware, byte-fair reactive scheduler; these are not separate mints.
repair_reactive_reserve_pct = 30
repair_reactive_hard_reserve_pct = 10

[s2s.overlay]
hello_interval_ms = 1000
hello_dead_interval_ms = 4000
lsa_max_age_ms = 120000
lsdb_sync_max_response_lsas = 2048
lsa_flood_pacing_interval_ms = 1000
lsa_flood_max_batch_lsas = 4096
lsa_refresh_reduction_enabled = true
lsa_unchanged_refresh_interval_secs = 90
routing_dynamic_spf_enabled = true
cost_rerun_min_interval_ms = 5000
cost_rerun_loss_ppm = 100000
route_transit_messages = true
ordered_lane_cap = 64
ordered_pending_window_packets = 1024
ordered_reorder_buffer_packets = 1024
ordered_repair_cache_packets = 1024
ordered_ack_timeout_ms = 250
ordered_retry_initial_ms = 250
ordered_retry_max_ms = 2000
ordered_retry_max_age_ms = 30000
ordered_retry_max_attempts = 16

[s2s.replications]
fallback_clock_tick_ms = 250
min_clock_tick_ms = 100
max_clock_tick_ms = 5000
delivery_tick_interval_ms = 50
propose_ttl_ms = 10000
propose_semaphore_size = 32
strict_max_catchup_ops = 256
# Must accommodate every persisted terminal decision plus its authenticated
# catchup envelope. If startup quarantines an old decision, raise the
# effective frame budget or migrate/compact the terminal journal and restart.
strict_max_catchup_bytes = 524288
# Aggregate retained-image bound for all resumable v2 strict snapshot source
# pins and receiver assemblies in one strict-topic runtime. This is not a
# capability switch; size it for concurrent transfers and the durable
# Channel/Ban state, not just one snapshot.
strict_max_snapshot_transfer_bytes = 67108864
strict_bootstrap_retry_interval_ms = 500
# Retained for configuration compatibility; periodic steady-state polling is
# disabled in favor of evidence-driven repair.
strict_steady_state_catchup_interval_ms = 5000
pending_propose_ttl_ms = 20000
recovery_ttl_ms = 10000
owner_catchup_timeout_ms = 5000
# Retained for configuration compatibility; periodic owner anti-entropy is
# disabled in favor of bootstrap, membership, and observed-gap repair.
owner_anti_entropy_interval_ms = 30000
owner_max_catchup_ops = 256
catchup_max_in_flight_total = 8
catchup_max_in_flight_per_peer = 1
client_replication_max_in_flight = 32
blob_chunk_size = 65536
blob_request_timeout_ms = 10000
blob_offer_wait_ms = 250
blob_retry_interval_ms = 500
blob_max_parallel_peers = 3
blob_decay_interval_ms = 60000
blob_unused_grace_ms = 600000
bulk_retry_delay_ms = 250
bulk_max_in_flight_per_peer = 1
```

### QUIC S2S Protocol And Delivery

QUIC advertises `[s2s/2, s2s/1]` through ALPN. Upgraded peers select `s2s/2`.
A peer that supports only `s2s/1` uses the unchanged legacy single reliable
stream, including BestEffort traffic on that stream.

`s2s/2` uses three persistent reliable streams plus QUIC DATAGRAM:

| Requested service level and class | Delivery |
|---|---|
| `BestEffort`, any class | QUIC DATAGRAM |
| Non-BestEffort `Control` | Control stream |
| Non-BestEffort `HighPriority` | HighPriority stream |
| Non-BestEffort `Regular` | Regular stream |

BestEffort overrides the class for delivery selection, while the frame retains
the class for inbound queue selection. FIFO ordering applies within each
reliable lane only; there is no cross-lane ordering guarantee. The reliable
lanes have equal Quinn priority, and session Ping, Pong, KeepAlive, and Bye
traffic is confined to Control.

Each QUIC DATAGRAM contains exactly one frame without a stream length prefix.
DATAGRAM is unreliable and may be lost or reordered. It is not retransmitted,
fragmented, or automatically repaired by the transport, and an oversized item
is never moved to a reliable lane after enqueue. BestEffort application
sequencing and repair remain responsible where applicable. Under queue
pressure, older DATAGRAM traffic is evicted to retain the newest traffic.

DATAGRAM may use configured stateless L1 compression when permitted by the
send options, but does not negotiate or use adaptive dictionaries. The three
reliable lanes maintain independent adaptive dictionary state. Streams and
DATAGRAM share the same congestion controller and path capacity, and Quinn
schedules queued DATAGRAM frames before stream frames; the separate lanes are
not bandwidth reservations.

The setup timeout applies after v2 has been negotiated. A v2 lane or DATAGRAM
capability failure closes the connection rather than retrying `s2s/1` inside
that connection. Existing v1 sessions stay v1 until reconnect. During a rolling
upgrade, retain dual-stack support for at least one rollback window and remove
v1 only after active-v1 and newly-negotiated-v1 metrics have both remained zero
for that entire window.

The DATAGRAM buffer values default to 65536 send bytes and 262144 receive
bytes; nonzero values below 1200 are rejected. Zero disables that local Quinn
DATAGRAM direction, but ALPN still offers `s2s/2`, so zero is not a protocol
rollback switch. A zero receive buffer prevents advertising the DATAGRAM
support required by v2. A zero send buffer also prevents the complete v2
mapping. Negotiated v2 setup therefore fails when either buffer is zero. Keep
both values nonzero for normal v2 operation. Legacy
peers that advertise only `s2s/1` can still negotiate v1.

For every `BestEffort` route, raw UDP and the DATAGRAM delivery path on an
eligible `s2s/2` QUIC session form the preferred datagram tier when the
complete frame fits. The requested routing metric chooses between eligible raw
UDP and QUIC DATAGRAM paths, giving them equal tier priority. Eligible datagram
paths stay ahead of TCP, KCP, and legacy `s2s/1` QUIC streams. Reliable
fallback is used only when datagrams are unavailable, do not fit the frame, or
have degraded or blocked health. Probing and viable datagram paths remain
eligible; lack of samples alone does not force reliable fallback. Strict
`s2s/2` streams never carry BestEffort; TCP and KCP provide compatible reliable
fallback when no legacy QUIC stream is available.

QUIC DATAGRAM is a delivery path on the existing QUIC session, not a separate
physical `TransportKind`; it shares that connection's network path, congestion
controller, and capacity. For BestEffort, only a legacy `s2s/1` QUIC stream is
eligible as a QUIC reliable fallback alongside TCP and KCP. An item is sent on
a reliable lane only after routing selects that delivery path; DATAGRAM enqueue
failure does not silently convert it to a reliable lane.

The Prometheus counter `shitspeak_s2s_delivery_path_selections_total`
distinguishes logical selections with bounded `path` values such as
`quic_datagram` and `quic_stream`. Physical QUIC RTT, packet loss, and health
metrics remain shared under `TransportKind::Quic`; delivery-path telemetry does
not model DATAGRAM as a second physical link.

BestEffort datagram health is a shadow-only hysteretic state (`probing`,
`healthy`, `suspect`, or `blocked`) and never removes a candidate. Raw UDP uses
the `best_effort_datagram_effective_loss_*_ppm` weighted effective-loss
thresholds, not raw-loss cutoffs. QUIC DATAGRAM instead uses path-local app
queue rejection and writer failure. Quinn buffer pressure, too-large events,
and ingress validation remain separate diagnostic counters. No DATAGRAM ACK,
on-time delivery, or end-to-end packet-loss signal exists. Aggregate QUIC
stream RTT/loss does not drive the QUIC DATAGRAM state, and the observer does
not affect routing or KCP behavior.

QUIC DATAGRAM requires `best_effort_datagram_suspect_bad_windows` distinct
completed one-second bad windows before entering `suspect`; up to 64 completed
windows are replayed in order. Recovery requires new completed healthy windows
spanning `best_effort_datagram_recover_healthy_ms`. Repeated reads of one window
do not advance either gate. Stale evidence returns the observer to `probing`
without clearing the recovery latch. Session replacement starts a tokenized
evidence generation and ignores late outcomes from the replaced session.
Status reports the last scored generation separately from newer
diagnostic-only generations. JSON status and bounded
`shitspeak_s2s_datagram_path_*` Prometheus gauges expose state, reason, score,
confidence, window counters, pending temporal progress, transitions, and
freshness.

The preference does not weaken admission checks. Unhealthy or otherwise
unusable datagram paths are excluded, and the QUIC DATAGRAM path is not a
candidate when the encoded frame exceeds its current maximum DATAGRAM size.
If no eligible datagram candidate remains, normal stream fallback applies. For
every BestEffort route, KCP's measured cost is increased by
`best_effort_kcp_cost_penalty_pct` (25% by default), while unmeasured KCP is
ordered after QUIC and TCP. KCP remains available when its adjusted metric
wins or it is the only fallback. `Reliable` traffic is unaffected. After KCP
fails away or closes for no forward progress, expiring high-priority
conversational voice requires fresh KCP acknowledgement/RTT progress before
admitting it again. An unexpected QUIC DATAGRAM enqueue failure still does not
convert the item to a reliable lane within that connection.

Voice-path stickiness applies to expiring conversational voice traffic. The
timing values must be nonzero, and `voice_path_idle_reset_ms` must be at least
the larger of the hold and challenger-confirmation values. These settings are
loaded at startup; restart the node after changing them. Set
`voice_path_stickiness_enabled = false` and restart to use the legacy routing
behavior as a rollback/kill switch. An eligible datagram path may replace a
reliable incumbent immediately. Minimum hold and challenger confirmation
continue to govern other path changes, and an unusable incumbent can still be
escaped immediately.

S2S inbound and outbound transport queues are adaptive and byte-budgeted. The
old `inbound_*_capacity` and `outbound_capacity` knobs are still accepted for
compatibility, but they act as minimum budget hints rather than hard message
counts.

Voice admission and reorder protection scale from the live top-level
`max_users` value at each new reservation; changing it does not rebuild queues
or evict already admitted work. The primary voice ingress budget is
`clamp(max_users * 512 B, 256 KiB, 4 MiB)`. The proactive lane is one eighth of
that, clamped to `32 KiB..512 KiB`; tracked reorder speakers are
`clamp(max_users * 2, 1024, 16384)`; and the proactive credit burst is
`clamp(primary / 32, 16 KiB, 128 KiB)`. At `max_users = 5000`, that yields a
2.5 MiB primary lane, 320 KiB proactive lane, 10,000 tracked speakers, and an
80 KiB proactive burst. A capacity decrease blocks only future admission.

Originals and reactive repairs use the primary lane. Proactive copies use the
lower-priority lane and are shed before primary traffic when capacity is
exhausted. An original mints one conserved repair byte for every four encoded
original bytes only after the aggregate primary transport accepts the send. A
failed primary send mints no credit and queues no proactive or tail repair.
Proactive and reactive payloads both pay their encoded byte size from the same
25% mint, which remains capped by the dynamic burst.

`repair_reactive_reserve_pct` (30 by default) is the reactive/tail entitlement
as a percentage of the total repair mint; the remainder is proactive
entitlement. Proactive work may borrow unused reactive entitlement, except for
`repair_reactive_hard_reserve_pct` (10 by default), and stops borrowing when
reactive demand appears. The hard reserve must not exceed the reactive reserve,
and neither may exceed 100. Configure `repair_max_extra_copies_per_frame` only
in the supported `0..2` range.

`strict_bootstrap_retry_interval_ms` gates strict startup and partition-heal
history-election retries. `strict_steady_state_catchup_interval_ms` and
`owner_anti_entropy_interval_ms` remain accepted for configuration
compatibility, but no longer schedule background catchup. Steady-state repair
is driven by observed gaps or stalls. Owner replication frames are retained on
an end-to-end acknowledged overlay lane between those repair events.

`transport_ttl_ms`, `repair_transport_ttl_ms`, and `repair_request_ttl_ms` are
the remote S2S voice delivery budget. They are not a local listener playout
delay. Set all three explicitly when the deployment includes long-haul links;
the documented long-haul profile uses `750` ms. `repair_cache_ms` must cover that
delivery window and the time needed to request a repair; it is `1600` ms in the
deployment configuration.

Remote voice is released immediately after S2S sequence ordering. The server
buffers only an observed sequence gap for its short per-speaker repair window;
clients own media pacing and jitter buffering. Legacy
`remote_playout_min_ms`, `remote_playout_max_ms`,
`remote_playout_p99_margin_ms`, and `remote_playout_idle_reset_ms` keys are
accepted as ignored no-ops for one release and should be removed from deployment
configuration.

The tracked `config.toml` enables the documented long-haul profile explicitly.
The S2S dashboard reports deadline translation, expiry, and clock-offset
fallbacks through `shitspeak_s2s_distribution_events_total`, labeled by local
node, original tree source, profile, service tag, bounded group kind, edge
direction, event, and bounded result. Direct peer clock health is available as
`shitspeak_s2s_distribution_peer_clock_{offset,uncertainty}_us` and
`shitspeak_s2s_distribution_peer_clock_estimate_age_seconds`, labeled by local
`source` and direct `peer`. The tree-edge gauge is a sum of local tree
snapshots; it is not a count of unique cluster edges. The dashboard's separate
active-edge stat deduplicates sent tree-voice traffic by directed
`source`/`destination` within its selected traffic window.

Per-edge tree traffic comes from
`shitspeak_s2s_debug_packet_io_{packets,bytes}_total`, filtered to
`application.voice.tree.original` and `application.voice.tree.repair` with
`direction="sent"`. It exposes original and repair frames/bytes separately by
directed edge without adding group or tree-version label cardinality.

Adaptive voice protection observability uses bounded labels.
`shitspeak_s2s_voice_ingress_admission_drops_total` retains the bounded `class`
label, while `shitspeak_s2s_voice_proactive_events_total` uses bounded `kind`
and `result` labels to distinguish ordinary copies from terminal-tail work and
credit exhaustion from queue pressure. Grafana shows proactive queue and credit
utilization per node because those limits are enforced locally.
`shitspeak_s2s_voice_receive_events_total{result="speaker_state_drop"}` reports
a dynamic speaker-cap admission refusal.

The hierarchical allocator exports conserved credit lifecycle bytes through
`shitspeak_s2s_voice_repair_credit_bytes_total{stage}`, and proactive versus
reactive allocation through
`shitspeak_s2s_voice_repair_allocator_class_bytes_total{class,stage}`. Fair
allocation is visible through
`shitspeak_s2s_voice_repair_allocator_destination_bytes_total{peer,stage}`.
`peer` is the bounded `u16` cluster node identity; session, user, address, and
channel identifiers are never labels. Current balances, reserve, directional
debt to each repair class, and active destination count are exported as
allocator gauges. Borrowing and repayment totals remain class-stage counters.
Lifecycle counters preserve the ledger's quarter-byte precision, so their
Prometheus values may have `.25`, `.5`, or `.75` fractional byte components.

Reactive scheduler observability uses the bounded counter
`shitspeak_s2s_voice_reactive_scheduler_events_total{event}`, where `event` is
one of `granted`, `credit_wait`, `retry_deferred`, `deadline_expired`,
`cancelled`, or `shutdown`. Unlabeled gauges report aggregate
`shitspeak_s2s_voice_reactive_scheduler_queued_items`,
`shitspeak_s2s_voice_reactive_scheduler_queued_encoded_bytes`,
`shitspeak_s2s_voice_reactive_scheduler_active_destinations`,
`shitspeak_s2s_voice_reactive_scheduler_oldest_wait_microseconds`, and
`shitspeak_s2s_voice_reactive_scheduler_max_starvation_rounds`. They expose
bounded allocator health without adding session, request, or destination labels.

The exact ledger invariant, evaluated in quarter-byte units, is
`minted = available + tentatively_reserved + committed + cap_discarded`.
`reserved` and `refunded` are transition counters used to derive outstanding
tentative credit; they are not additional credit sources.

Proactive allocation has two deterministic phases. The existing UDP-only
primary loss/jitter thresholds and deterministic sampling generate copy demand;
utility ranking does not create new demand or generate QUIC-DATAGRAM copies.
One first-copy candidate per destination receives the
private/fair-share phase. Remaining candidates compete for shared overflow by
marginal utility per encoded byte. A candidate needs a measured alternate with
a distinct first hop and enough remaining deadline. Its estimated repair
probability multiplies `1 - alternate_loss` by an on-time estimate that rises
from zero at the alternate latency to one at latency plus three times jitter.
The remaining factors are a 1.25 terminator value, a 0.75 same-transport or 1.0
different-transport diversity proxy, deadline urgency from 1.0 through 1.5,
strong diminishing returns for the second copy, and bounded fairness aging;
later copies have zero utility. Zero-utility candidates are discarded before
body encoding or credit reservation.

One route-quality batch and deadline origin are captured before the primary
send. Continuously waiting overflow receives 3.125% aging per allocator round,
capped at 1.5 times after 16 rounds; service resets the age, and an inactive
destination returns unaged. Deterministic frame-sequence/destination/copy
tie-breaking makes input iteration order irrelevant. These values rank a
conserved budget; they never mint additional credit and instantaneous credit
balance is not a path-quality input.

The proactive utility is deliberately a proxy. First-hop and transport
differences cannot prove that two routes are independent farther downstream,
and the route-quality snapshot cannot observe the receiver's actual arrival
time. The alternate's measured latency, loss, and jitter estimate on-time
benefit; they are not delivery acknowledgements. A second copy can therefore
still traverse correlated underlay even though its marginal utility is lower.

Reactive NACK responses and tail attempts pay exact full-byte credit and enter
one per-frame scheduler before receiving a tentative permit. Frames are EDF
within each destination. Across destinations, byte-deficit round robin uses a
1200-byte quantum and orders peers by least-recent actual grant, then node ID,
so a stream of small frames cannot monopolize service merely by producing more
requests. Retry traffic is bounded per destination in each 100 ms epoch to half
of that destination's active share of reactive capacity, with a one-quantum
minimum. Over-cap retries defer rather than being shed. Temporary credit
exhaustion parks work until mint, refund, a new request, the next retry epoch,
or its absolute local deadline. Only an actual permit advances service and
retry accounting. Expired work receives no permit; transport timeout,
rejection, or cancellation refunds tentative credit, and every retry must
obtain a new permit. This is destination-fair EDF, not global EDF across all
peers.

NACK ranges and tail suffixes advance one frame at a time. The current frame
from every ready key reaches the shared permit scheduler before transport
concurrency is applied; a successful frame then requeues the next sequence
behind other ready work. Retry-cap deferral and an unaffordable large request
do not hide eligible fresh or smaller work for the same destination. Actual
transport attempts remain bounded, with at most one repair send per destination
in flight.

A repair requester writes its remaining local actionable-gap window into the
NACK as a relative duration. On receipt, the responder creates a local deadline
bounded by its configured repair transport/cache lifetime, merges overlapping
requests using the earliest such deadline, and applies the deadline to each
frame and transport attempt. This avoids shared-clock assumptions, but time
spent carrying the request over the network is not subtracted from the encoded
duration. The deadline is therefore a bounded scheduling hint, not proof that a
repair will reach the receiver before playout.

Tail repair has protected reactive credit, primary sender admission, separate
sender pressure state, and bounded concurrent dispatch. It intentionally stays
proactive-marked on the wire: a healthy reorder stream rejects ordinary
reactive repair when no gap has been observed, while a tail terminator has no
later packet that could reveal its loss. Consequently tail repair is not yet a
fully isolated reactive receiver lane even though its sender-side scheduling
and accounting are reactive.

There is deliberately no unminted startup seed. During cold start, the first
full-frame NACK may therefore be credit-shed until accepted originals have
accumulated enough repair credit. This preserves the exact 25% payload ceiling
instead of hiding startup repair bytes outside the ledger.

See [Clustering](clustering.md) for certificate generation, local demos, and S2S operational notes.

## Web Gateway

The browser gateway is disabled by default and requires the relevant Cargo feature at build time.

```toml
[web]
enabled = true
listen = "0.0.0.0:64739"
public_base_url = "https://voice.example.com:64739"
allowed_origins = ["https://voice.example.com"]

[web.auth]
modes = ["password", "sso"]
password_enabled = true

[web.auth.sso]
issuer = "https://idp.example.com"
jwks_url = "https://idp.example.com/.well-known/jwks.json"
audience = "shitspeak-web"
subject_claim = "sub"
username_claim = "preferred_username"
groups_claim = "groups"

[web.webrtc]
max_speaker_ssrcs = 64
audio_bitrate = 64000
ice_servers = [
  { urls = ["stun:stun.l.google.com:19302"] },
  { urls = ["turn:turn.example.com:3478"], username = "turn-user", credential = "turn-secret" },
]
```

MoQ/WebTransport uses a separate QUIC listener:

```toml
[web.moq]
enabled = true
listen = "0.0.0.0:64740"
public_url = "https://voice.example.com:64740/web/moq"
cert_path = "/etc/shitspeak-rs/webtransport/server-cert.pem"
key_path = "/etc/shitspeak-rs/webtransport/server-key.pem"
max_speaker_tracks = 64
audio_bitrate = 64000
```

See [Web gateway](web-gateway.md).

## Loki Logging

```toml
[logging.loki]
enabled = true
url = "http://localhost:3100"
filter = "shitspeak_rs=debug"
labels = { environment = "prod" }

batch_size = 128
flush_interval_ms = 1000
queue_capacity = 4096
request_timeout_ms = 5000
retry_cache_capacity = 4096
retry_initial_interval_ms = 1000
retry_max_interval_ms = 30000
```

`url` can be a Loki base URL or the full `/loki/api/v1/push` endpoint. If `filter` is omitted, Loki shipping defaults to this crate's logs instead of all dependency logs. Loki streams automatically include `node_id`, the resolved S2S node id.

Loki also accepts `tenant_id`, `username`, `password`, and `bearer_token` in
the same table. A bearer token takes precedence over basic authentication.

## Metrics And Remote Write

```toml
[observability.metrics]
enabled = true
listen = "0.0.0.0:64751"
path = "/metrics"

[observability.metrics.remote_write]
enabled = true
url = "http://localhost:9009/api/v1/push"
labels = { environment = "prod" }
interval_ms = 15000
batch_size = 4096
retry_cache_capacity = 16384
request_timeout_ms = 5000
retry_initial_interval_ms = 1000
retry_max_interval_ms = 30000
```

Authentication options:

```toml
[observability.metrics.remote_write]
tenant_id = "tenant"
username = "grafana-cloud-user-or-org-id"
password = "grafana-cloud-token"
# bearer_token = "token"
```

If `bearer_token` is set, it takes precedence over basic auth. See [Observability](observability.md).

## Hot Reload

The server watches `config.toml`, configured authenticator module paths, and the client TLS certificate/key parent directories. Reloads are debounced briefly so atomic replacement workflows work cleanly.

Reloaded successfully at runtime:

- `welcome_text`
- `root_channel_name`
- `max_bandwidth`
- `max_users`
- `authenticator`
- `cert_path` and `key_path` for new client TLS handshakes
- `s2s.overlay.route_transit_messages`
- `udp_voice_enabled`
- `udp_ping_enabled`
- `udp_ping_user_count_scope`
- `client_idle_timeout_secs`
- `required_groups`
- `geoip`
- `send_permission_info`
- `hide_users_without_traverse`
- `hide_channels_without_traverse`
- `show_node_id_for_superusers`
- `[acl]` behavior toggles
- `[privacy]` certificate hash protection and secret
- additions to `server_entrypoints`

Restart-sensitive settings include base listener changes, most existing listener remaps, S2S identity and most S2S transport/listen settings, storage paths, `client_log_max_entries`, `auth_finalization_concurrency`, feature-gated web startup, metrics server startup, Loki startup, and public registration startup.

If a reload fails to parse or a staged authenticator/TLS identity cannot be loaded, the previous live configuration stays active.

## Troubleshooting Examples

### The Server Cannot Read TLS Files

Use paths relative to the process working directory or absolute paths:

```toml
cert_path = "/etc/shitspeak-rs/tls/server-cert.pem"
key_path = "/etc/shitspeak-rs/tls/server-key.pem"
```

### WASM File Access Returns Unavailable

File imports require at least one access directory:

```toml
[authenticator.wasm]
path = "auth/auth.wasm"
file_access_dir = ["auth/files"]
working_dir = "auth/files"
```

### UDP Ping Shows Cluster Counts On A Single Node

Use local scope:

```toml
udp_ping_user_count_scope = "local"
```

### S2S Advertise Fails With An Unspecified Address

Listen on wildcard addresses, but advertise routable addresses:

```toml
[s2s]
tcp_listen = "0.0.0.0:64739"
tcp_advertise = "node-1.example.com:64739"
```
