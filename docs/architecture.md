# Architecture

[Docs index](README.md)

ShitSpeak is organized around a Mumble-compatible client server, a persistent shared state core, optional authentication backends, optional browser access, and experimental server-to-server clustering.

## Startup Flow

`src/main.rs`:

- Installs the Rustls AWS-LC crypto provider.
- Initializes logging.
- Loads `config.toml`.
- Builds the reloadable authenticator.
- Creates `Server`.
- Starts the config watcher.
- Runs until shutdown.

`src/server.rs` owns listeners, runtime state, reload handling, web gateway startup, S2S startup, registration, and graceful shutdown.

## Core Modules

- `src/config.rs`: configuration schema, defaults, environment loading, and parsing tests.
- `src/server.rs`: accept loops, TLS setup, UDP sockets, runtime state, reloads, and orchestration.
- `src/client`: client sessions, state, handlers, groups, voice targets, stats, and Mumble voice crypto.
- `src/messages`: protobuf message reading, writing, encoders, errors, and macros.
- `src/voice`: UDP voice packet decoding, routing, ping handling, and datagram batching.
- `src/channel_repository.rs` and `src/channel_handler.rs`: channel tree state, ACL-aware operations, logs, and snapshots.
- `src/client_repository.rs`: client state repository and broadcast support.
- `src/blob_store.rs`: channel and session blob storage.
- `src/api`: authenticator traits, demo/exec/WASM backends, and authenticator JSON contracts.
- `src/privacy.rs`: certificate hash remapping.
- `src/observability.rs` and `src/logging.rs`: metrics, remote write, and Loki shipping.
- `src/register.rs`: public Mumble server-list registration.

## Server-To-Server Modules

- `src/s2s/transport`: peer transport sessions, TLS identity, TCP/KCP/QUIC/UDP endpoints, metrics, compression, and connection management.
- `src/s2s/overlay`: neighbor liveness, link-state database, route calculation, messaging, delivery, and persistence.
- `src/s2s/replications`: strict and owner-mode replication, catchup, topics, and blob replication.
- `src/s2s/application`: voice, text message, plugin data, moderation, and user stats application-level propagation.
- `src/s2s/status.rs`: HTML status page and Prometheus topology metrics.

## Web Modules

The web gateway is feature-gated:

- `web` feature: WebRTC peer/session/signaling/voice modules.
- `moq` feature: MoQ/WebTransport support, also enabling `web`.

Code lives under `src/web`, with browser assets in `web/demo` and SDK assets in `web/sdk`.

## Persistent State

Runtime state is mostly in repositories and broadcast logs. Durable state is written below `blob_storage_dir` and, for cluster-specific state, `s2s.persistence_dir`.

See [Persistence](persistence.md).

## Configuration Reload

`src/config_watcher.rs` watches `config.toml`, authenticator module paths, and client TLS identity paths. Reload is staged in `Server::reload_config()` so invalid config, invalid TLS identity, or invalid authenticator replacements do not replace the current live state.
