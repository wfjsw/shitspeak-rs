# Configuration

[Docs index](README.md)

The server loads `config.toml` from the working directory. Environment variables can override settings with the `SHITSPEAK_` prefix and underscores for nested keys.

For example, `SHITSPEAK_PRIVACY_CERTIFICATE_HASH_SECRET` maps to the nested privacy certificate hash secret form.

## Common Settings

- `listen`: default client TCP and UDP listener address.
- `cert_path` and `key_path`: TLS identity for Mumble client connections.
- `max_users`, `max_bandwidth`, `max_text_message_length`, and `max_image_message_length`: client-facing limits.
- `root_channel_name` and `default_channel`: initial channel behavior.
- `udp_voice_enabled` and `udp_ping_enabled`: UDP voice and status behavior.
- `blob_storage_dir`: persistent channel, client, blob, and authenticator state root.
- `required_groups`: authentication groups required to connect.
- `[authenticator]`: demo, exec, or WASM authentication backend.
- `[privacy]`: certificate hash privacy controls.
- `[acl]`: ACL behavior toggles.
- `[s2s]`: server-to-server clustering.
- `[web]`: optional browser gateway.
- `[logging.loki]`: optional Loki log shipping.
- `[observability.metrics]`: optional Prometheus metrics and remote write.

The checked-in `config.toml` is a good reference for all currently exposed settings and their default intent.

## Authentication Backend

The authenticator is selected with:

```toml
[authenticator]
backend = "demo" # demo, wasm, exec
```

Backend-specific settings live under `[authenticator.wasm]` or `[authenticator.exec]`. See [Authentication](authentication.md).

## Virtual Entrypoints

`[[server_entrypoints]]` can add extra TCP/UDP listener pairs or map TLS SNI names to virtual server ids:

```toml
[[server_entrypoints]]
server_id = "tenant-a"
listen = "0.0.0.0:64748"
udp_ping_status_server_id = "tenant-a"
sni = ["tenant-a.example.com"]
```

An authenticator can also return `virtual_server_id` for a user. This is useful for multi-tenant deployments that share one process.

## Hot Reload

The server watches `config.toml`, the configured authenticator module path, and the client TLS certificate/key parent directories. Reloads are debounced briefly so atomic replacement workflows work cleanly.

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

Startup-only or restart-sensitive settings include listener identity, S2S identity and most S2S transport/listen settings, storage paths, feature-gated web startup, metrics server startup, and public registration startup.

If a reload fails to parse or a staged authenticator/TLS identity cannot be loaded, the previous live configuration stays active.

## Certificate Hash Privacy

`[privacy].protect_certificate_hashes` controls what non-superuser clients see in other users' `UserState.hash` fields:

- `false`: disabled.
- `true` or `"irreversible"`: stable one-way remap.
- `"reversible"`: stable AES-based remap that can be restored with the shared secret.

The viewer's own certificate hash is sent unchanged. In clustered deployments, configure the same secret on every node:

```toml
[privacy]
protect_certificate_hashes = "irreversible"
certificate_hash_secret = "replace-with-a-long-random-cluster-secret"
```

Prefer environment storage for secrets when possible:

```powershell
$env:SHITSPEAK_PRIVACY_CERTIFICATE_HASH_SECRET = "replace-with-a-long-random-cluster-secret"
```

## Public Server Registration

Public registration activates only when the registration fields are complete:

```toml
register_name = "My ShitSpeak Server"
register_password = "registry-password"
register_url = "mumble://voice.example.com:64738"
register_hostname = "voice.example.com"
register_location = "New York, USA"
```

`udp_ping_enabled` should remain enabled for normal public listing behavior.
