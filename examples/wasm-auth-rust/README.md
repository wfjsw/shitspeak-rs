# Rust WASM Authenticator Example

This crate builds a `wasm32-unknown-unknown` module compatible with `authenticator_wasm_path`.

```powershell
rustup target add wasm32-unknown-unknown
cargo build --manifest-path examples/wasm-auth-rust/Cargo.toml --target wasm32-unknown-unknown --release
```

Then point the server at:

```toml
authenticator_wasm_path = "examples/wasm-auth-rust/target/wasm32-unknown-unknown/release/shitspeak_wasm_auth_rust_example.wasm"
```

Local demo behavior:

- `admin` with password `secret` is accepted as user `1` with the `admin` group and superuser privileges.
- `guest` is accepted as a guest user.
- usernames starting with `fetch:` call the host HTTPS `fetch` import as an example external auth flow.

The host runs authenticator calls on Wasmtime's async engine. The Rust export functions keep the required pointer/length ABI, while the example policy and fetch helpers are async internally.

Responses may include `max_bandwidth` to override the configured bandwidth limit for that authenticated client.
