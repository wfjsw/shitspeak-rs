# ShitSpeak

ShitSpeak is a Rust voice server compatible with Mumble clients. It provides TLS client connections, UDP voice and ping handling, channel and ACL management, persistent server state, optional custom authentication, and experimental multi-node server-to-server operation.

The Cargo package and default binary are both named `shitspeak-rs`.

## Status

This project is under active development. The checked-in `config.toml` is intended for local development and testing. Review it carefully before exposing a server publicly, especially authentication, TLS certificates, public registration, persistence, and clustering settings.

## Quick Start

Generate local test certificates, build, and run:

```powershell
cargo run --example gen-test-certs
cargo build
cargo run
```

The development config listens on `0.0.0.0:64738`. Connect a Mumble client to `localhost:64738`.

For more logging during development:

```powershell
$env:RUST_LOG = "debug"
cargo run
```

## Documentation

Start with the documentation index:

- [Documentation index](docs/README.md)
- [Getting started](docs/getting-started.md)
- [Configuration](docs/configuration.md)
- [Authentication](docs/authentication.md)
- [Persistence](docs/persistence.md)
- [Clustering](docs/clustering.md)
- [Web gateway](docs/web-gateway.md)
- [Observability](docs/observability.md)
- [Deployment](docs/deployment.md)
- [Development](docs/development.md)
- [Architecture](docs/architecture.md)

## Common Commands

```powershell
cargo fmt
cargo check
cargo test
cargo bench
```

Optional feature builds:

```powershell
cargo build --features web
cargo build --features moq
```

## Repository Map

- `src/`: Rust server, protocol, client, voice, auth, web, and S2S modules.
- `config.toml`: local development configuration.
- `examples/`: certificate generators, authenticator examples, and Docker Compose demos.
- `web/`: browser demo and JavaScript SDK assets.
- `deploy/`: Grafana and Prometheus provisioning examples.
- `packaging/`: systemd service example.
- `benches/`: Criterion benchmark suites.

## License

No license file is currently included in this repository.
