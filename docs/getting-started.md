# Getting Started

[Docs index](README.md)

ShitSpeak runs as the `shitspeak-rs` binary and reads `config.toml` from the current working directory.

## Requirements

- Rust stable with Cargo.
- A native C toolchain for Rust dependencies on your platform.
- PowerShell or PowerShell Core for the included helper scripts.
- Node.js and npm only for the AssemblyScript WASM authenticator example.
- The Rust `wasm32-unknown-unknown` target only for the Rust WASM authenticator example.

The build uses `prost-build` and `protoc-bin-vendored`, so a separate system Protobuf compiler is normally not required.

## Local Run

From the repository root:

```powershell
cargo check
cargo run
```

The checked-in development configuration listens on `0.0.0.0:64738`. Connect a Mumble client to `localhost` on port `64738`.

Before starting the server, provide a TLS certificate and key at the paths
configured in `config.toml`.

## Logging

Set `RUST_LOG` before starting the server:

```powershell
$env:RUST_LOG = "debug"
cargo run
```

The server also supports optional Loki shipping. See [Observability](observability.md).

## Useful Next Steps

- Configure TLS, limits, authentication, and persistence in [Configuration](configuration.md).
- Replace the demo authenticator before public deployment with [Authentication](authentication.md).
- Review [Deployment](deployment.md) before exposing a server.
