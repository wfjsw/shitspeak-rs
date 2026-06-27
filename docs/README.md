# ShitSpeak Documentation

This directory is the main documentation set for ShitSpeak. The top-level [README](../README.md) is intentionally short; deeper operational and development details live here.

## Start Here

- [Getting started](getting-started.md): build, generate local certificates, run the server, and connect with a Mumble client.
- [Configuration](configuration.md): config loading, environment overrides, hot reload behavior, and common settings.
- [Authentication](authentication.md): demo, exec, and WebAssembly authenticators.
- [Persistence](persistence.md): what is stored under `blob_storage_dir`, backup guidance, and tuning knobs.

## Operators

- [Deployment](deployment.md): Docker, systemd, public registration, and production checklist.
- [Clustering](clustering.md): server-to-server transport, overlay routing, replication, certificates, and local demos.
- [Observability](observability.md): logging, Loki, Prometheus metrics, remote write, S2S status pages, and Grafana artifacts.
- [Web gateway](web-gateway.md): browser signaling, WebRTC, MoQ/WebTransport, SDK, and demo assets.

## Contributors

- [Development](development.md): build/test/bench commands, repository conventions, generated code, and feature flags.
- [Architecture](architecture.md): source layout and how the major subsystems fit together.

## Existing Specialized Docs

- [Systemd unit notes](../packaging/systemd/README.md)
- [Grafana provisioning notes](../deploy/grafana/README.md)
- [16-node Docker Compose demo](../examples/docker-compose-16node/README.md)
- [Rust WASM authenticator example](../examples/wasm-auth-rust/README.md)
- [AssemblyScript WASM authenticator example](../examples/wasm-auth-assemblyscript/README.md)
