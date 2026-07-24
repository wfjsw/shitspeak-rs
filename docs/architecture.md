# Architecture

[Docs index](README.md)

ShitSpeak is organized around a Mumble-compatible client server, a persistent shared state core, optional authentication backends, optional browser access, and experimental server-to-server clustering.

## Startup Flow

`src/main.rs` selects the optional web extensions and calls
`shitspeak_runtime::run_server_with_extensions()`. The runtime then:

- Installs the Rustls AWS-LC crypto provider.
- Initializes logging.
- Loads `config.toml`.
- Builds the reloadable authenticator.
- Creates `Server`.
- Starts the config watcher.
- Runs until shutdown.

`crates/shitspeak-runtime/src/server.rs` owns listeners, runtime state, reload
handling, web gateway startup, S2S startup, registration, and graceful
shutdown.

## Workspace Layout

- The root package provides the `shitspeak-rs` server binary, re-exports the
  runtime library, and provides the `s2s-forwarder` binary.
- `crates/shitspeak-runtime-config` defines configuration loading, defaults,
  and validation.
- `crates/shitspeak-runtime` contains server orchestration, client sessions,
  voice handling, channel/client repositories, persistence integration,
  authentication wiring, logging, observability, registration, and runtime
  S2S integration.
- `crates/shitspeak-auth`, `shitspeak-state`, `shitspeak-messages`,
  `shitspeak-client-crypto`, and `shitspeak-core` provide the corresponding
  focused libraries used by the runtime.
- `crates/shitspeak-proto` owns the protobuf definitions and generated Rust
  bindings.

## Server-To-Server Modules

- `crates/shitspeak-s2s-transport`: peer transport sessions, TLS identity,
  TCP/KCP/QUIC/UDP endpoints, metrics, compression, and connection management.
- `crates/shitspeak-s2s`: overlay routing, replication, application-layer
  propagation, and status support.
- `crates/shitspeak-runtime/src/s2s`: connects the S2S libraries to server
  state, clients, voice, and observability.

## Web Modules

The web gateway is feature-gated:

- `web` feature: WebRTC peer/session/signaling/voice modules.
- `moq` feature: MoQ/WebTransport support, also enabling `web`.

The Rust implementation is in `crates/shitspeak-web`; browser assets live in
`web/demo` and the JavaScript SDK lives in `web/sdk`.

## Persistent State

Runtime state is mostly in repositories and broadcast logs. Durable state is written below `blob_storage_dir` and, for cluster-specific state, `s2s.persistence_dir`.

See [Persistence](persistence.md).

## Configuration Reload

`crates/shitspeak-runtime/src/config_watcher.rs` watches `config.toml`,
authenticator module paths, and client TLS identity paths. Reload is staged in
`Server::reload_config()` so invalid config, invalid TLS identity, or invalid
authenticator replacements do not replace the current live state.
