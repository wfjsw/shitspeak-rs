# Project Overview

- **Name**: shitspeak-rs
- **Type**: Rust async server implementing the Mumble voice protocol over TLS
- **Runtime**: tokio (full features)
- **TLS**: tokio-rustls + aws-lc-rs
- **Protobuf**: prost (Mumble.proto, MumbleUDP.proto)
- **Edition**: Rust 2021

## Key Dependencies
- `enumflags2` with serde for bitflag permissions
- `maxminddb` for GeoIP lookups
- `ppp` for PROXY protocol support
- `rustls` 0.23 with `tokio-rustls` 0.26
- `reqwest` 0.12 for HTTP blob store
- `tracing` + `tracing-subscriber` for structured logging
- `chrono` with serde for timestamps
- `async-trait` for async trait support
- `thiserror` for error derivation
- `message_macro` — local proc-macro crate at `src/messages/macros/`

## Build
- `build.rs` uses `prost-build` to compile `protos/Mumble.proto` and `protos/MumbleUDP.proto`
- `chrono` is a build dependency for embedding build date
- Benchmarks use `criterion` with `acl` benchmark harness
