# Web Gateway

[Docs index](README.md)

The optional browser gateway is configured under `[web]` and is disabled by default.

It includes:

- WebSocket signaling and authentication policy support.
- WebRTC peer and voice bridge modules.
- Optional MoQ and WebTransport support behind the `moq` Cargo feature.
- Browser demo assets under `web/demo`.
- JavaScript SDK assets under `web/sdk`.

## Build Features

WebRTC support:

```powershell
cargo build --features web
```

MoQ/WebTransport support:

```powershell
cargo build --features moq
```

The `moq` feature includes the `web` feature.

## Configuration

```toml
[web]
enabled = false
listen = "0.0.0.0:64739"
public_base_url = "https://localhost:64739"
allowed_origins = ["https://localhost:64739"]

[web.auth]
modes = ["password", "sso"]
password_enabled = true

[web.webrtc]
max_speaker_ssrcs = 64
audio_bitrate = 64000
ice_servers = [
  { urls = ["stun:stun.l.google.com:19302"] },
]
```

SSO configuration lives under `[web.auth.sso]`.

## MoQ And WebTransport

MoQ uses a separate QUIC/WebTransport listener:

```toml
[web.moq]
enabled = false
listen = "0.0.0.0:64740"
public_url = "https://localhost:64740/web/moq"
max_speaker_tracks = 64
audio_bitrate = 64000
```

When `cert_path` and `key_path` are omitted in `[web.moq]`, the main server TLS identity is used. Browser WebTransport clients need a certificate they can validate for the configured origin.

## Demo And SDK

- `web/demo`: static demo and smoke test assets.
- `web/sdk`: JavaScript SDK, TypeScript declarations, and tests.
