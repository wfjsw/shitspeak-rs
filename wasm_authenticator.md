# WASM Authenticator

The binary can load a Wasmtime authenticator by setting `authenticator_wasm_path` in `config.toml`, or by using the equivalent `SHITSPEAK_AUTHENTICATOR_WASM_PATH` environment key. If the value is omitted, the server uses the built-in demo authenticator.

The WASM module is hot-reloaded when `config.toml` changes or when the configured `.wasm` file is replaced. Reload is staged first: if the new module cannot be read or compiled, the old authenticator remains active.

The host does not link WASI. Guest modules only receive the imports listed below.

Authenticator calls run on Wasmtime's async engine. The exported guest functions still use the pointer/length ABI below, but host imports such as `fetch` may suspend the WebAssembly call while I/O is in flight instead of blocking a Tokio worker thread.

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
  "max_bandwidth": null,
  "texture_url": null,
  "comment_url": null
}
```

`max_bandwidth`, when present, overrides the configured `max_bandwidth` value advertised to that authenticated client.

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
  "body": "{\"user\":\"alice\"}",
  "timeout_ms": 5000
}
```

The response buffer receives JSON containing `ok`, `status`, `status_text`, `headers`, `body`, and `error`. The return value is the response byte length. If the supplied response buffer is too small, the return value is the negative required length. Only `https://` URLs are allowed.

## Host Cache And State Imports

The host also provides these imports under both `env` and `shitspeak`:

```text
cache_get(key_ptr: i32, key_len: i32, response_ptr: i32, response_capacity: i32) -> i32
cache_put(key_ptr: i32, key_len: i32, value_ptr: i32, value_len: i32) -> i32
cache_delete(key_ptr: i32, key_len: i32) -> i32
cache_clear() -> i32

state_get(key_ptr: i32, key_len: i32, response_ptr: i32, response_capacity: i32) -> i32
state_put(key_ptr: i32, key_len: i32, value_ptr: i32, value_len: i32) -> i32
state_delete(key_ptr: i32, key_len: i32) -> i32
state_clear() -> i32
```

`cache_*` is per-loaded-authenticator, in-memory, and lost on reload. Keys are up to 1024 bytes and values are 1 byte to 64 KiB.

`state_*` is durable key/value storage for the authenticator. It is available only when `blob_storage_dir` is configured; data is stored under a host-owned `wasm_authenticator` subdirectory. Keys are up to 1024 bytes and values are 1 byte to 16 MiB. When no persistence directory is configured, state operations return `0`.

For `*_get`, `0` means missing or unavailable, a positive value is the number of bytes written, a negative value is the required response size, and `-1` means error. For `*_put`, `*_delete`, and `*_clear`, `1` means changed/success, `0` means unavailable or absent, and `-1` means error.

## Examples

Example authenticators are available in:

- `examples/wasm-auth-rust`
- `examples/wasm-auth-assemblyscript`
