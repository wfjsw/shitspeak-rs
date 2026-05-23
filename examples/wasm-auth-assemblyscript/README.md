# AssemblyScript WASM Authenticator Example

This package builds an AssemblyScript module compatible with `authenticator_wasm_path`.

```powershell
cd examples/wasm-auth-assemblyscript
npm install
npm run build
```

Then point the server at:

```toml
authenticator_wasm_path = "examples/wasm-auth-assemblyscript/build/auth.wasm"
```

Local demo behavior:

- `admin` with password `secret` is accepted as user `1` with the `admin` group.
- `guest` is accepted as a guest user.
- usernames starting with `fetch:` call the host HTTPS `fetch` import as an example external auth flow.

The example uses a tiny hand-rolled JSON reader to keep the AssemblyScript sample dependency-free. Use a real JSON library for production policy code.
