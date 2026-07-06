# Configuration

[Docs index](README.md)

ShitSpeak reads `config.toml` from the current working directory. The checked-in `config.toml` is a local-development reference with comments for most available settings.

This page explains how the file is loaded, what the major settings do, and gives copyable examples for common deployment shapes.

## Loading Rules

The server loads:

1. `config.toml` from the process working directory.
2. Environment variable overrides with the `SHITSPEAK_` prefix.

Use underscores for nested keys:

```powershell
$env:SHITSPEAK_LISTEN = "0.0.0.0:64738"
$env:SHITSPEAK_MAX_USERS = "250"
$env:SHITSPEAK_AUTHENTICATOR_BACKEND = "wasm"
$env:SHITSPEAK_AUTHENTICATOR_WASM_PATH = "auth/auth.wasm"
$env:SHITSPEAK_PRIVACY_CERTIFICATE_HASH_SECRET = "replace-with-a-long-random-secret"
```

TOML remains the clearest format for arrays and tables. Environment variables are best for simple scalar values and secrets.

## Minimal Local Config

These are the required top-level fields plus a small practical baseline:

```toml
listen = "0.0.0.0:64738"
register_name = "ShitSpeak Local"

cert_path = "cert.pem"
key_path = "key.pem"

send_version = true
send_build_info = true
send_os_info = true

allowed_proxies = []
min_client_version = 0
max_users = 100

welcome_text = "Welcome to ShitSpeak"
root_channel_name = "Root"
default_channel = 0

blob_storage_dir = "data"

[authenticator]
backend = "demo"
```

Generate local test certificates with:

```powershell
cargo run --example gen-test-certs
```

The generated certificates are for local testing only.

## Production-Style Single Node

This example keeps the shape small while showing the settings that usually matter first:

```toml
listen = "0.0.0.0:64738"
register_name = "Example Voice"

cert_path = "/etc/shitspeak-rs/tls/cert.pem"
key_path = "/etc/shitspeak-rs/tls/key.pem"

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
# Default: floor(3rd root(active CPU count)), minimum 1.
# auth_finalization_concurrency = 1
pending_delete_timeout_ms = 5000

blob_storage_dir = "/var/lib/shitspeak-rs"

required_groups = ["member"]
send_permission_info = true
hide_users_without_traverse = true

[authenticator]
backend = "wasm"

[authenticator.wasm]
path = "/etc/shitspeak-rs/auth/auth.wasm"

[privacy]
protect_certificate_hashes = "irreversible"
certificate_hash_secret = "replace-with-a-long-random-cluster-secret"
# Prefer SHITSPEAK_PRIVACY_CERTIFICATE_HASH_SECRET for real deployments.

[acl]
debug_acl_enter = false
explicit_enter_deny_overrides_write = true
preserve_write_acl_on_edit = false
grant_temp_channel_creator_acl = true
reevaluate_speak_on_acl_change = true
```

## Top-Level Server Settings

### Listener And TLS

```toml
listen = "0.0.0.0:64738"
cert_path = "cert.pem"
key_path = "key.pem"
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

## Timeouts

```toml
client_idle_timeout_secs = 30
authenticate_timeout_ms = 30000
# Default: floor(3rd root(active CPU count)), minimum 1.
# auth_finalization_concurrency = 1
pending_delete_timeout_ms = 5000
```

`authenticate_timeout_ms` starts after TLS setup. `auth_finalization_concurrency` limits how many clients can concurrently create UDP crypt setup state, run authenticator backend work, and perform the initial sync/publish path. When omitted, it defaults to `floor(3rd root(active CPU count))` with a minimum of 1. `pending_delete_timeout_ms` controls rollback timing for pending two-phase channel deletes.

## Persistence

```toml
blob_storage_dir = "data"
channel_log_max_entries = 10000
client_log_max_entries = 10000
channel_snapshot_every_ops = 10
channel_snapshot_every_secs = 60
channel_wal_compaction_expire_count = 2000
```

`blob_storage_dir` stores channel snapshots, write-ahead logs, client state logs, channel blobs, session blob cache data, user channel cache data, and WASM authenticator durable state.

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

The server keeps a reusable pool of WASM instances and creates more as queued authenticator work needs them. `auth_finalization_concurrency` controls how many login authenticator calls can run at once. The same limit also throttles per-client UDP crypt setup so connection spikes do not generate unbounded key setup work. Instance creation itself remains serialized. `file_access_dir` bounds file access from the WASM raw stream imports. When it is empty, file stream imports are unavailable.

### Exec Authenticator

```toml
[authenticator]
backend = "exec"

[authenticator.exec]
mode = "exec_long_running" # exec_ephemeral, exec_long_running
long_running_request_mode = "serialized" # serialized, async
command = "auth-helper"
args = ["--config", "auth/config.toml"]
working_dir = "auth"
timeout_ms = 30000
max_response_bytes = 16777216
# uid = 1001
# gid = 1001
```

Exec authenticators exchange JSON over stdin/stdout. `long_running_request_mode = "serialized"` keeps one request in flight at a time for compatibility. `async` allows multiple in-flight requests and requires each response to echo the request's `request_id`. See [Authentication](authentication.md) for request/response contracts and WASM imports.

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
```

`send_permission_info` includes per-client channel enter hints in `ChannelState` messages. `hide_users_without_traverse` hides users whose current channel the viewer cannot traverse.

### ACL Behavior Toggles

```toml
[acl]
debug_acl_enter = false
explicit_enter_deny_overrides_write = true
preserve_write_acl_on_edit = false
grant_temp_channel_creator_acl = true
reevaluate_speak_on_acl_change = true
```

- `debug_acl_enter`: when true, superusers ignore channel Enter denies.
- `explicit_enter_deny_overrides_write`: when true, explicit Enter denies remain denied even if Write would otherwise imply Enter.
- `preserve_write_acl_on_edit`: when true, registered non-superuser ACL editors keep a personal Write fallback if their edit would remove their own Write permission.
- `grant_temp_channel_creator_acl`: when true, temporary channel creators receive local ACL grants for missing Write, Enter, and Speak permissions.
- `reevaluate_speak_on_acl_change`: when true, ACL edits reevaluate Speak for clients currently in the changed channel subtree and update their `UserState.suppress` state.

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
$env:SHITSPEAK_PRIVACY_CERTIFICATE_HASH_SECRET = "replace-with-a-long-random-cluster-secret"
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
persistence_dir = "s2s-state"

tcp_listen = "0.0.0.0:64739"
kcp_listen = "0.0.0.0:64740"
quic_listen = "0.0.0.0:64741"
udp_listen = "0.0.0.0:64742"

tcp_advertise = "node-1.example.com:64739"
kcp_advertise = "node-1.example.com:64740"
quic_advertise = "node-1.example.com:64741"
udp_advertise = "node-1.example.com:64742"

status_http_listen = "0.0.0.0:64750"

seed_addresses = [
  { transport = "tcp", addr = "node-2.example.com:64739" },
  { transport = "quic", addr = "node-3.example.com:64741" },
]
```

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

Transport and replication tuning examples:

```toml
[s2s.transport]
ping_interval_secs = 2
idle_ping_interval_secs = 10
self_seed_quarantine_secs = 3600
max_dial_attempts_per_peer_tick = 1
max_outgoing_connections = 1024
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

[s2s.overlay]
hello_interval_ms = 1000
hello_dead_interval_ms = 4000
routing_dynamic_spf_enabled = true
route_transit_messages = true

[s2s.replications]
propose_ttl_ms = 10000
propose_semaphore_size = 32
strict_max_catchup_ops = 256
blob_chunk_size = 65536
bulk_retry_delay_ms = 250
bulk_max_in_flight_per_peer = 1
```

S2S inbound and outbound transport queues are adaptive and byte-budgeted. The
old `inbound_*_capacity` and `outbound_capacity` knobs are still accepted for
compatibility, but they act as minimum budget hints rather than hard message
counts.

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
cert_path = "/etc/shitspeak-rs/webtransport/cert.pem"
key_path = "/etc/shitspeak-rs/webtransport/key.pem"
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

`url` can be a Loki base URL or the full `/loki/api/v1/push` endpoint. If `filter` is omitted, Loki shipping defaults to this crate's logs instead of all dependency logs.

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
- `[acl]` behavior toggles
- `[privacy]` certificate hash protection and secret
- additions to `server_entrypoints`

Restart-sensitive settings include base listener changes, most existing listener remaps, S2S identity and most S2S transport/listen settings, storage paths, `auth_finalization_concurrency`, feature-gated web startup, metrics server startup, Loki startup, and public registration startup.

If a reload fails to parse or a staged authenticator/TLS identity cannot be loaded, the previous live configuration stays active.

## Troubleshooting Examples

### The Server Cannot Read TLS Files

Use paths relative to the process working directory or absolute paths:

```toml
cert_path = "/etc/shitspeak-rs/tls/cert.pem"
key_path = "/etc/shitspeak-rs/tls/key.pem"
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
