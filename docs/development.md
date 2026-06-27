# Development

[Docs index](README.md)

This project is a Rust workspace-style crate with the default binary and package named `shitspeak-rs`.

## Commands

```powershell
cargo fmt
cargo check
cargo test
cargo bench
```

Run the server locally:

```powershell
cargo run --example gen-test-certs
cargo run
```

Feature builds:

```powershell
cargo build --features web
cargo build --features moq
```

## Generated Code

`build.rs` compiles protobuf definitions from `src/protos` into generated Rust modules included by `src/lib.rs` and `src/main.rs`:

- `mumble_proto`
- `mumble_udp`
- `s2s_transport_proto`
- `s2s_overlay_proto`
- `s2s_replication_proto`
- `s2s_application_proto`

The build uses vendored `protoc`, so contributors normally do not need to install a separate Protobuf compiler.

## Benchmarks

Criterion benchmarks live under `benches`:

- `acl`
- `voice_hotpath`
- `voice_e2e`
- `voice_microbatch`
- `s2s_compression`

Run all benchmarks:

```powershell
cargo bench
```

## Integration Tests

Integration test harnesses and scenarios live under `src/integration_tests`. They cover authentication, ACLs, channel operations, voice behavior, user stats, self actions, moderation actions, and S2S transport/overlay/replication behavior.

## Vendored Dependencies

The repository patches `kcp` and `tokio_kcp` to local vendored crates under `vendor/`.

## Documentation Workflow

The top-level `README.md` should stay short. Add task-specific details under `docs/` and link them from the [docs index](README.md).
