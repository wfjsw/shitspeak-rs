# WASM Authenticator

The WASM authenticator guide has moved into the navigable documentation set:

- [Authentication](docs/authentication.md)
- [WASM authenticator contract](docs/authentication.md#wasm-authenticator-contract)

Current configuration uses the nested authenticator layout:

```toml
[authenticator]
backend = "wasm"

[authenticator.wasm]
path = "auth.wasm"
file_access_dir = ["auth-files"]
working_dir = "auth-files"
```
