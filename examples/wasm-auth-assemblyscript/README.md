# AssemblyScript WASM Authenticator Example

This package builds an AssemblyScript module compatible with the ShitSpeak WASM authenticator backend.

```powershell
cd examples/wasm-auth-assemblyscript
npm install
npm run build
```

Then point the server at the generated module:

```toml
[authenticator]
backend = "wasm"

[authenticator.wasm]
path = "<path-to-compiled-wasm-module>"
```

Local demo behavior:

- `admin` with password `secret` is accepted as user `1` with the `admin` group and superuser privileges.
- `guest` is accepted as a guest user.
- usernames starting with `fetch:` call the host HTTPS `fetch` import as an example external auth flow.

The host runs authenticator calls on Wasmtime's async engine. AssemblyScript still imports `fetch` as a normal core-WASM function; the host may suspend and resume the Wasmtime invocation while the HTTPS request is in flight.

Responses may include `max_bandwidth` to override the configured bandwidth limit for that authenticated client.

The example uses a tiny hand-rolled JSON reader to keep the AssemblyScript sample dependency-free. Use a real JSON library for production policy code.

See the full contract in [Authentication](../../docs/authentication.md#wasm-authenticator-contract).
