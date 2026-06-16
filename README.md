# ShitSpeak

ShitSpeak is a Rust voice server compatible with Mumble clients. It provides TLS client connections, UDP voice and ping handling, channel and ACL management, persistent server state, optional WebAssembly authentication, and experimental multi-node server-to-server operation.

The Cargo package and default binary are both named `shitspeak-rs`.

## Status

This project is under active development. The checked-in `config.toml` is intended for local development and testing; review it carefully before exposing a server publicly. Some clustering, browser gateway, and MoQ/WebTransport settings are experimental or disabled by default.

## Features

- Mumble-compatible client protocol over TCP with Rustls.
- UDP voice and ping support with Mumble voice crypto.
- Channel, ACL, ban, user state, and text message handling.
- Persistent channel and client state using snapshots and write-ahead logs.
- Hot reload for selected runtime settings, including client TLS identity for new handshakes.
- Optional authentication through Wasmtime WebAssembly modules.
- Certificate hash privacy controls for non-superuser client views.
- Experimental server-to-server transport, overlay routing, replication, and status components.
- Optional browser gateway scaffolding with WebRTC support and MoQ/WebTransport work behind Cargo features.
- Criterion benchmark suites for ACL and voice-path performance.

## Requirements

- Rust stable with Cargo.
- A native C toolchain for Rust dependencies on your target platform.
- PowerShell or PowerShell Core for the included deployment scripts.
- Node.js and npm only for the AssemblyScript WASM authenticator example.
- The Rust `wasm32-unknown-unknown` target only for the Rust WASM authenticator example.

The build uses `prost-build` and `protoc-bin-vendored`, so a separate system Protobuf compiler is not normally required.

## Quick Start

Generate local test certificates:

```powershell
cargo run --example gen-test-certs
```

Build and check the server:

```powershell
cargo check
cargo build
```

Run the server from the repository root:

```powershell
cargo run
```

By default, the development configuration listens on `0.0.0.0:64738`. Connect a Mumble client to `localhost` on port `64738`.

The generated certificates are for local testing only.

To increase logging during development:

```powershell
$env:RUST_LOG = "debug"
cargo run
```

## Configuration

The server loads `config.toml` from the working directory. Settings can also be overridden with environment variables using the `SHITSPEAK_` prefix and underscores for nested keys.

Common settings include:

- `listen`: client TCP and UDP listener address.
- `cert_path` and `key_path`: TLS identity for Mumble client connections.
- `max_users`, `max_bandwidth`, and message length settings: client limits.
- `root_channel_name`: display name for channel `0`.
- `udp_voice_enabled` and `udp_ping_enabled`: UDP behavior.
- `blob_storage_dir`: persistent channel, client, and blob data location.
- `authenticator_wasm_path`: optional custom WASM authenticator module.
- `authenticator_file_access_dir`: optional filesystem access roots for the WASM authenticator.
- `authenticator_working_dir`: working directory for relative authenticator file paths.
- `[privacy].protect_certificate_hashes`: certificate hash privacy mode.
- `[s2s]`, `[s2s.transport]`, `[s2s.overlay]`, and `[s2s.replications]`: clustered operation.
- `[web]`: optional browser gateway.

Selected settings are hot reloaded when `config.toml` changes. The client TLS identity from `cert_path` and `key_path` is also hot reloaded for new handshakes when either file changes. Listener addresses, node identity, storage paths, and other startup resources require a restart.

### Certificate Hash Privacy

Certificate-hash privacy is configured with `[privacy].protect_certificate_hashes`.

Supported values are:

- `false`: disable protection.
- `true` or `"irreversible"`: use a stable one-way remap.
- `"reversible"`: use an AES-based stable remap that can be restored with the shared secret.

Only other users' `UserState.hash` values are remapped for non-superuser clients. The viewer's own hash is sent unchanged. In clustered deployments, configure the same `[privacy].certificate_hash_secret` on every node, or set `SHITSPEAK_PRIVACY_CERTIFICATE_HASH_SECRET`.

### Loki Logging

To ship logs to Grafana Loki, enable `[logging.loki]` in `config.toml` or set equivalent `SHITSPEAK_LOGGING_LOKI_*` environment variables:

```toml
[logging.loki]
enabled = true
url = "http://localhost:3100"
filter = "shitspeak_rs=debug"
labels = { environment = "dev" }
```

If `filter` is omitted, Loki shipping defaults to `shitspeak_rs=<level>`, so dependency logs are not sent unless you widen the directive explicitly. Failed pushes are retried from a bounded in-memory cache; tune `retry_cache_capacity`, `retry_initial_interval_ms`, and `retry_max_interval_ms` for larger deployments.

## Authentication

If `authenticator_wasm_path` is omitted, the server uses the built-in demo authenticator. For real deployments, provide a WASM authenticator that implements the host contract documented in `wasm_authenticator.md`.

Example authenticators are available in:

- `examples/wasm-auth-rust`
- `examples/wasm-auth-assemblyscript`

Build the Rust example:

```powershell
rustup target add wasm32-unknown-unknown
cargo build --manifest-path examples/wasm-auth-rust/Cargo.toml --target wasm32-unknown-unknown --release
```

Build the AssemblyScript example:

```powershell
cd examples/wasm-auth-assemblyscript
npm install
npm run build
```

When a configured WASM file changes, the reload path compiles the new module before activating it. If the new module cannot be loaded, the current authenticator remains active.

## Persistence

The default `blob_storage_dir` is `data`. This directory stores channel snapshots, write-ahead logs, channel blobs, session blob cache data, and `user_channel_cache.json` for TTL-bound last/listening channel restoration.

For durable deployments, back up this directory and place it on storage that survives process and host restarts.

Persistence tunables include:

- `channel_log_max_entries`
- `client_log_max_entries`
- `channel_snapshot_every_ops`
- `channel_snapshot_every_secs`
- `channel_wal_compaction_expire_count`

## Clustering

The server-to-server subsystem supports multi-node operation with transport metrics, overlay routing, state replication, and content-addressed channel blob transfer.

A clustered deployment must provide unique S2S certificates whose leaf certificate Common Name is the numeric node id, plus listener addresses, advertised addresses, seed peers, and a persistence directory for cluster state. When S2S is disabled or no S2S certificate is configured, the local node id defaults to `0`.

When `s2s.persistence_dir` is set, the transport caches the latest learned adaptive compression dictionary under that directory and renegotiates it with peers after restart.

Generate S2S test certificates with:

```powershell
cargo run --example gen-s2s-certs
```

The local 16-node Docker Compose example is under `examples/docker-compose-16node`.

## Browser Gateway

The optional browser gateway is configured with `[web]` and is disabled by default.

Gateway code includes:

- WebSocket signaling and authentication policy support.
- WebRTC peer and voice bridge modules.
- Optional MoQ and WebTransport support behind the `moq` Cargo feature.
- A browser demo under `web/demo`.
- JavaScript SDK assets under `web/sdk`.

Build with MoQ support when needed:

```powershell
cargo build --features moq
```

## Repository Layout

- `src/main.rs`: binary entry point, logging setup, configuration loading, authenticator setup, config watching, and graceful shutdown.
- `src/server.rs`: main server accept loops, runtime state, reload handling, web gateway startup, and client orchestration.
- `src/client`: client session state, message handlers, voice targets, groups, UDP state, and Mumble voice crypto integration.
- `src/messages`: protobuf message reading, writing, and helper macros.
- `src/voice`: UDP voice packet decoding, encoding, ping handling, routing, and datagram batching.
- `src/s2s`: server-to-server transport, overlay, replication, status, and test support modules.
- `src/web`: browser signaling, peer session, protocol, voice, and MoQ gateway code.
- `src/protos`: Mumble and internal server-to-server protobuf definitions.
- `examples`: certificate generators, WASM authenticator examples, and Docker Compose examples.
- `deploy`: deployment-specific scripts and generated configuration bundles.
- `web/demo` and `web/sdk`: browser demo and JavaScript SDK assets.
- `benches`: Criterion benchmark suites.

## Development

Common commands:

```powershell
cargo fmt
cargo check
cargo test
cargo bench
```

The VS Code workspace includes tasks for certificate generation, `cargo check`, and `cargo build`. The default launch profile generates local certificates before starting the debug server.

## Docker And Deployment

A Dockerfile is included at the repository root. There is also a local Docker Compose example under `examples/docker-compose-16node`.

Build the Linux musl binary from the repository root:

```powershell
cross build --target=x86_64-unknown-linux-musl --release
```

Generate or refresh the 16-node Compose material:

```powershell
pwsh examples/docker-compose-16node/generate-compose-16node.ps1 -Force
```

Start the cluster:

```powershell
docker compose -f examples/docker-compose-16node/compose.yaml up -d --build
```

Useful follow-up commands:

```powershell
docker compose -f examples/docker-compose-16node/compose.yaml ps
docker compose -f examples/docker-compose-16node/compose.yaml logs -f node-01
docker compose -f examples/docker-compose-16node/compose.yaml down -v
```

The generator writes `compose.yaml`, image files, shared certificates, per-node config and S2S key material, and `manifest.json` with host port assignments.

Node `N` publishes Mumble TCP and UDP on `localhost:20000 + N` and the S2S status page on `localhost:21000 + N`. For example, node 1 is reachable at `localhost:20001`, and its status page is available at `http://localhost:21001`.

## Security

- Do not use generated test certificates in production.
- Protect TLS private keys, S2S keys, authentication modules, and persistent data.
- Configure `allowed_proxies` only for trusted PROXY protocol senders.
- Use a production authenticator instead of the demo authenticator for any exposed service.
- Review public registration settings before enabling server-list registration.
- Review `config.toml` before deployment; the checked-in file is development-oriented.

## License

No license file is currently included in this repository.
