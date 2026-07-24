# Development

[Docs index](README.md)

This project is a Cargo workspace. The root package and default server binary
are named `shitspeak-rs`.

## Commands

```powershell
cargo fmt
cargo check
cargo test
cargo bench
```

The default `cargo check` and `cargo test` commands exercise the root package.
Before opening a change that touches a workspace library, run the full
workspace checks instead:

```powershell
cargo check --workspace --all-targets --locked
cargo test --workspace --all-targets --locked
```

Include the relevant optional feature when changing gateway code:

```powershell
cargo check --workspace --all-targets --features web --locked
cargo check --workspace --all-targets --features moq --locked
```

Run the server locally:

```powershell
cargo run
```

Provide a TLS certificate and key at the paths configured in `config.toml`
before starting the server.

Feature builds:

```powershell
cargo build --features web
cargo build --features moq
```

## Generated Code

`crates/shitspeak-proto/build.rs` compiles the definitions in
`crates/shitspeak-proto/protos` with vendored `protoc`. Cargo writes the
generated files to that crate's `OUT_DIR`, and
`crates/shitspeak-proto/src/lib.rs` exposes them as:

- `mumble_proto`
- `mumble_udp`
- `s2s_transport_proto`
- `s2s_overlay_proto`
- `s2s_upper_layer_proto`
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
- `fanout_vs_broadcast`

Run all benchmarks:

```powershell
cargo bench
```

## Integration Tests

Integration test harnesses and scenarios live under
`crates/shitspeak-runtime/src/integration_tests`. They cover authentication,
ACLs, channel operations, voice behavior, user stats, self actions,
moderation actions, and S2S transport/overlay/replication behavior.

## Vendored Dependencies

The repository patches `kcp` and `tokio_kcp` to local vendored crates under `vendor/`.

## Documentation Workflow

The top-level `README.md` should stay short. Add task-specific details under `docs/` and link them from the [docs index](README.md).
