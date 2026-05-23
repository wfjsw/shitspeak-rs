# WASM Authenticator

The binary can load a Wasmtime authenticator by setting `authenticator_wasm_path` in `config.toml`, or by using the equivalent `SHITSPEAK_AUTHENTICATOR_WASM_PATH` environment key. If the value is omitted, the server uses the built-in demo authenticator.

The WASM module is hot-reloaded when `config.toml` changes or when the configured `.wasm` file is replaced. Reload is staged first: if the new module cannot be read or compiled, the old authenticator remains active.

## Required Exports

The module must export:

```text
memory
alloc(len: i32) -> i32
authenticate(ptr: i32, len: i32) -> i64
```

`authenticate` receives a UTF-8 JSON request in guest memory and returns `(ptr << 32) | len`, where `ptr` and `len` describe a UTF-8 JSON response. An optional `dealloc(ptr: i32, len: i32)` export is called for request and response buffers when present.

Optional exports:

```text
language(ptr: i32, len: i32) -> i64
authenticate_external(ptr: i32, len: i32) -> i64
```

## Authenticate Request

```json
{
  "username": "alice",
  "password": "optional password",
  "auxiliary_data": {
    "certificate_hash_base64": null,
    "session_id": 1,
    "ip_address": "127.0.0.1",
    "version": { "major": 1, "minor": 5, "patch": 0 },
    "client_name": "Mumble",
    "os_name": "Windows",
    "os_version": "10"
  }
}
```

## Authenticate Response

```json
{
  "accepted": true,
  "user_id": 42,
  "display_name": "Alice",
  "groups": ["admin"],
  "virtual_server_id": null,
  "language": "en",
  "texture_url": null,
  "comment_url": null
}
```

For rejection, return `accepted: false` and `rejection` as `no_such_user`, `invalid_username`, `wrong_password`, or `retry_later`.

## HTTPS Fetch Import

The host provides `fetch` under both `env.fetch` and `shitspeak.fetch`:

```text
fetch(request_ptr: i32, request_len: i32, response_ptr: i32, response_capacity: i32) -> i32
```

The request is JSON:

```json
{
  "url": "https://auth.example.test/check",
  "method": "POST",
  "headers": { "content-type": "application/json" },
  "body_base64": "eyJ1c2VyIjoiYWxpY2UifQ==",
  "timeout_ms": 5000
}
```

The response buffer receives JSON containing `ok`, `status`, `headers`, `body_base64`, and `error`. The return value is the response byte length. If the supplied response buffer is too small, the return value is the negative required length. Only `https://` URLs are allowed.

## Examples

Example authenticators are available in:

- `examples/wasm-auth-rust`
- `examples/wasm-auth-assemblyscript`
